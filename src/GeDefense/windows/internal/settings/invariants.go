// STATUS: DIAMANT VGT SUPREME
package settings

import (
	"fmt"
	"reflect"
	"sort"
)

// valueBool returns the boolean control value from a sectioned value document.
func valueBool(values map[string]map[string]any, section, key string) (bool, bool) {
	sectionValues, exists := values[section]
	if !exists {
		return false, false
	}
	value, exists := sectionValues[key]
	if !exists {
		return false, false
	}
	typed, ok := value.(bool)
	return typed, ok
}

func valueInt(values map[string]map[string]any, section, key string) (int, bool) {
	sectionValues, exists := values[section]
	if !exists {
		return 0, false
	}
	value, exists := sectionValues[key]
	if !exists {
		return 0, false
	}
	typed, ok := value.(int)
	return typed, ok
}

func valueString(values map[string]map[string]any, section, key string) (string, bool) {
	sectionValues, exists := values[section]
	if !exists {
		return "", false
	}
	value, exists := sectionValues[key]
	if !exists {
		return "", false
	}
	typed, ok := value.(string)
	return typed, ok
}

func valueStringList(values map[string]map[string]any, section, key string) ([]string, bool) {
	sectionValues, exists := values[section]
	if !exists {
		return nil, false
	}
	value, exists := sectionValues[key]
	if !exists {
		return nil, false
	}
	typed, ok := value.([]string)
	return typed, ok
}

func setValue(values map[string]map[string]any, section, key string, value any) {
	if values[section] == nil {
		values[section] = make(map[string]any)
	}
	values[section][key] = value
}

// levelViolations evaluates the hard security floor of a protection level. An
// empty result means the value document is acceptable for that level. The
// custom level intentionally has no floor: its activation is explicitly
// confirmed and reported as custom.
func levelViolations(level string, values map[string]map[string]any) []string {
	if level == LevelCustom {
		return nil
	}
	violations := make([]string, 0, 16)
	requireBool := func(section, key, message string) {
		value, ok := valueBool(values, section, key)
		if !ok || !value {
			violations = append(violations, message)
		}
	}
	requireString := func(section, key, expected, message string) {
		value, ok := valueString(values, section, key)
		if !ok || value != expected {
			violations = append(violations, message)
		}
	}
	requireListContains := func(section, key, expected, message string) {
		value, ok := valueStringList(values, section, key)
		if !ok || !containsString(value, expected) {
			violations = append(violations, message)
		}
	}

	// Monitor floor: passive observation still requires the detection and
	// firewall baseline.
	requireBool(SectionDefender, "realtimeProtection", "defender realtime protection is required at monitor level")
	requireBool(SectionFirewall, "domainProfileEnabled", "domain firewall profile must stay enabled")
	requireBool(SectionFirewall, "privateProfileEnabled", "private firewall profile must stay enabled")
	requireBool(SectionFirewall, "publicProfileEnabled", "public firewall profile must stay enabled")
	requireString(SectionFirewall, "defaultInboundAction", "block", "inbound firewall default must remain block")

	if level != LevelGuarded && level != LevelSovereign {
		return violations
	}

	// Guarded floor.
	requireBool(SectionDefender, "behaviorProtection", "defender behavior protection is required at guarded level")
	requireBool(SectionDefender, "networkProtection", "defender network protection is required at guarded level")
	requireBool(SectionDefender, "puaProtection", "PUA protection is required at guarded level")
	requireBool(SectionDefender, "controlledFolderAccess", "controlled folder access is required at guarded level")
	cloud, cloudOK := valueString(values, SectionDefender, "cloudBlockLevel")
	if !cloudOK || cloudBlockLevelRank[cloud] < cloudBlockLevelRank["high"] {
		violations = append(violations, "cloud block level must be at least high at guarded level")
	}
	sample, sampleOK := valueString(values, SectionDefender, "sampleSubmission")
	if !sampleOK || sample == "never" {
		violations = append(violations, "sample submission must not be disabled at guarded level")
	}
	requireBool(SectionMHX, "autoTerminate", "verified automatic process termination is required at guarded level")
	requireListContains(SectionHardening, "enabledComponents", "DefenderCloud", "hardening component DefenderCloud is required at guarded level")
	requireListContains(SectionHardening, "enabledComponents", "ASR", "hardening component ASR is required at guarded level")
	requireListContains(SectionHardening, "enabledComponents", "Firewall", "hardening component Firewall is required at guarded level")
	feedActions, feedOK := valueStringList(values, SectionThreatIntelligence, "feedActions")
	actionByFeed := feedActionIndex(feedActions)
	for _, feed := range threatFeedBlockingIDs {
		if !feedOK || actionByFeed[feed] != "block" {
			violations = append(violations, fmt.Sprintf("threat feed %s must remain in block mode at guarded level", feed))
		}
	}

	if level != LevelSovereign {
		return violations
	}

	// Sovereign floor.
	if !cloudOK || cloudBlockLevelRank[cloud] < cloudBlockLevelRank["highPlus"] {
		violations = append(violations, "cloud block level must be at least highPlus at sovereign level")
	}
	if !sampleOK || (sample != "safe" && sample != "always") {
		violations = append(violations, "sample submission must remain safe or always at sovereign level")
	}
	requireString(SectionMHX, "aggressiveness", LevelSovereign, "MHX aggressiveness must be sovereign at sovereign level")
	requireString(SectionMHX, "applicationControl", "enforce", "application control must be enforced at sovereign level")
	requireBool(SectionMHX, "networkDefaultDeny", "network default deny must be active at sovereign level")
	requireBool(SectionThreatIntelligence, "blockingEnabled", "threat intelligence blocking must stay enabled at sovereign level")
	requireBool(SectionKinetic, "persistedArmed", "persisted Kinetic readiness is required at sovereign level")
	enabled, enabledOK := valueStringList(values, SectionHardening, "enabledComponents")
	if !enabledOK || len(enabled) != len(hardeningComponentIDs) {
		violations = append(violations, "all hardening components must remain enabled at sovereign level")
	}
	return violations
}

func feedActionIndex(actions []string) map[string]string {
	index := make(map[string]string, len(actions))
	for _, token := range actions {
		feed, action, cut := splitToken(token)
		if cut {
			index[feed] = action
		}
	}
	return index
}

func splitToken(token string) (string, string, bool) {
	for position := 0; position < len(token); position++ {
		if token[position] == ':' {
			return token[:position], token[position+1:], true
		}
	}
	return token, "", false
}

// valuesEqual compares two canonical value documents.
func valuesEqual(left, right map[string]map[string]any) bool {
	return reflect.DeepEqual(left, right)
}

// activeLevelFromProfiles resolves the level of the active profile, falling
// back to the documented default level when no profile matches.
func activeLevelFromProfiles(activeProfileID string, profiles []Profile) string {
	for _, profile := range profiles {
		if profile.ID == activeProfileID {
			return profile.Level
		}
	}
	return DefaultProfileID
}

func findProfile(profiles []Profile, id string) (Profile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

// builtinProfiles returns the canonical built-in protection profiles. They are
// code-owned: a persisted file can never weaken them.
func builtinProfiles() []Profile {
	defaults := defaultValues()

	monitorValues := cloneValues(defaults)
	setValue(monitorValues, SectionMHX, "aggressiveness", LevelMonitor)
	setValue(monitorValues, SectionMHX, "autoTerminate", false)
	setValue(monitorValues, SectionMHX, "applicationControl", "off")
	setValue(monitorValues, SectionMHX, "networkDefaultDeny", false)
	setValue(monitorValues, SectionKinetic, "persistedArmed", false)

	guardedValues := cloneValues(defaults)

	sovereignValues := cloneValues(defaults)
	setValue(sovereignValues, SectionDefender, "cloudBlockLevel", "zeroTolerance")
	setValue(sovereignValues, SectionMHX, "aggressiveness", LevelSovereign)
	setValue(sovereignValues, SectionMHX, "applicationControl", "enforce")
	setValue(sovereignValues, SectionMHX, "networkDefaultDeny", true)
	setValue(sovereignValues, SectionKinetic, "persistedArmed", true)
	setValue(sovereignValues, SectionThreatIntelligence, "pollIntervalSeconds", 21600)

	return []Profile{
		{
			ID:          LevelMonitor,
			Name:        "Monitor",
			Description: "Passive Beobachtung mit Protokollierung; keine aktive Prozess- oder Netzwerkantwort.",
			Level:       LevelMonitor,
			BuiltIn:     true,
			Values:      monitorValues,
		},
		{
			ID:          LevelGuarded,
			Name:        "Guarded",
			Description: "Verifizierte Standardverteidigung mit begrenzter, identitätsgeprüfter Antwort.",
			Level:       LevelGuarded,
			BuiltIn:     true,
			Values:      guardedValues,
		},
		{
			ID:          LevelSovereign,
			Name:        "Sovereign",
			Description: "Maximalprofil mit durchgesetzter Anwendungssteuerung und Netzwerk-Default-Deny.",
			Level:       LevelSovereign,
			BuiltIn:     true,
			Values:      sovereignValues,
		},
	}
}

func builtinProfile(id string) (Profile, bool) {
	for _, profile := range builtinProfiles() {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

// sortedValueKeys returns stable keys for a section value map.
func sortedValueKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
