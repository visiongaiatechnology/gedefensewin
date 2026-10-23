// STATUS: DIAMANT VGT SUPREME
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	// ErrValidation reports a rejected request: unknown section/field, wrong
	// type, out-of-bounds number, invalid enum, invalid list item or invalid
	// reason/identifier.
	ErrValidation = errors.New("settings validation rejected")
	// ErrConflict reports a request that is structurally valid but violates the
	// active protection level contract, the profile lifecycle rules or the
	// applier's supported surface.
	ErrConflict = errors.New("settings conflict rejected")
	// ErrUnavailable reports that no applier is wired, so an apply cannot be
	// enforced. Settings are then never silently persisted.
	ErrUnavailable = errors.New("settings applier unavailable")
	// ErrPersistence reports a failed atomic write or unreadable state.
	ErrPersistence = errors.New("settings persistence failed")
)

type catalogIndex struct {
	controlByID       map[string]Control
	controlsBySection map[string]map[string]Control
	sections          map[string]Section
}

func buildCatalogIndex() catalogIndex {
	index := catalogIndex{
		controlByID:       make(map[string]Control),
		controlsBySection: make(map[string]map[string]Control),
		sections:          make(map[string]Section),
	}
	for _, section := range sectionDefinitions() {
		index.sections[section.ID] = section
		index.controlsBySection[section.ID] = make(map[string]Control)
	}
	for _, control := range allControls() {
		index.controlByID[control.ID] = control
		short := shortControlID(control.ID)
		if sectionControls, exists := index.controlsBySection[control.Section]; exists {
			sectionControls[short] = control
		}
	}
	return index
}

func (index catalogIndex) control(id string) (Control, bool) {
	control, exists := index.controlByID[id]
	return control, exists
}

func (index catalogIndex) sectionControl(section, key string) (Control, bool) {
	sectionControls, exists := index.controlsBySection[section]
	if !exists {
		return Control{}, false
	}
	control, exists := sectionControls[key]
	return control, exists
}

func (index catalogIndex) knownSection(section string) bool {
	_, exists := index.sections[section]
	return exists
}

// canonicalSection resolves a caller-supplied section identifier
// case-insensitively to its catalog spelling (for example "threatintelligence"
// resolves to "threatIntelligence").
func (index catalogIndex) canonicalSection(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if _, exists := index.sections[trimmed]; exists {
		return trimmed, true
	}
	for id := range index.sections {
		if strings.EqualFold(id, trimmed) {
			return id, true
		}
	}
	return "", false
}

// defaultValues returns a fresh canonical default-value document.
func defaultValues() map[string]map[string]any {
	values := make(map[string]map[string]any)
	for _, section := range sectionDefinitions() {
		values[section.ID] = make(map[string]any)
	}
	for _, control := range allControls() {
		values[control.Section][shortControlID(control.ID)] = cloneValue(control.Default)
	}
	return values
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case []string:
		copied := make([]string, len(typed))
		copy(copied, typed)
		return copied
	case []any:
		copied := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				copied = append(copied, text)
			}
		}
		return copied
	default:
		return value
	}
}

func cloneValues(values map[string]map[string]any) map[string]map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]map[string]any, len(values))
	for section, sectionValues := range values {
		cloned[section] = make(map[string]any, len(sectionValues))
		for key, value := range sectionValues {
			cloned[section][key] = cloneValue(value)
		}
	}
	return cloned
}

// normalizeControlValue converts a decoded JSON value into the canonical typed
// value of the control after full validation. Unknown types are rejected.
func normalizeControlValue(control Control, raw any) (any, error) {
	var (
		normalized any
		err        error
	)
	switch control.Type {
	case TypeBool:
		normalized, err = normalizeBool(raw)
	case TypeInteger:
		normalized, err = normalizeInteger(control, raw)
	case TypeEnum:
		normalized, err = normalizeEnum(control, raw)
	case TypeStringList:
		normalized, err = normalizeStringList(control, raw)
	default:
		err = errors.New("unsupported control type")
	}
	if err != nil {
		return nil, err
	}
	if control.custom != nil {
		return control.custom(normalized)
	}
	return normalized, nil
}

func normalizeBool(raw any) (any, error) {
	value, ok := raw.(bool)
	if !ok {
		return nil, errors.New("boolean value required")
	}
	return value, nil
}

func normalizeInteger(control Control, raw any) (any, error) {
	value, err := integerValue(raw)
	if err != nil {
		return nil, err
	}
	if control.Min != nil && value < *control.Min {
		return nil, fmt.Errorf("value %d below minimum %d", value, *control.Min)
	}
	if control.Max != nil && value > *control.Max {
		return nil, fmt.Errorf("value %d above maximum %d", value, *control.Max)
	}
	return int(value), nil
}

func integerValue(raw any) (int64, error) {
	switch typed := raw.(type) {
	case int:
		return int64(typed), nil
	case int64:
		return typed, nil
	case json.Number:
		parsed, err := strconv.ParseInt(typed.String(), 10, 64)
		if err != nil {
			return 0, errors.New("whole number required")
		}
		return parsed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || math.Abs(typed) > float64(1<<53) {
			return 0, errors.New("whole number required")
		}
		return int64(typed), nil
	default:
		return 0, errors.New("whole number required")
	}
}

func normalizeEnum(control Control, raw any) (any, error) {
	text, ok := raw.(string)
	if !ok {
		return nil, errors.New("string value required")
	}
	candidate := strings.ToLower(strings.TrimSpace(text))
	for _, option := range control.Options {
		if strings.ToLower(option) == candidate {
			return option, nil
		}
	}
	return nil, errors.New("value is not a catalogued option")
}

func normalizeStringList(control Control, raw any) (any, error) {
	maximum := control.maxItems
	if maximum <= 0 {
		maximum = 32
	}
	maximumLength := control.maxLength
	if maximumLength <= 0 {
		maximumLength = 64
	}
	var items []any
	switch typed := raw.(type) {
	case nil:
		return []string{}, nil
	case []any:
		items = typed
	case []string:
		items = make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	default:
		return nil, errors.New("string list required")
	}
	if len(items) > maximum {
		return nil, fmt.Errorf("list exceeds %d items", maximum)
	}
	normalized := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("string list item must be a string")
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, errors.New("empty string list item rejected")
		}
		if len(text) > maximumLength {
			return nil, fmt.Errorf("string list item exceeds %d characters", maximumLength)
		}
		if !validPrintable(text) {
			return nil, errors.New("string list item contains control characters")
		}
		if _, duplicate := seen[text]; duplicate {
			return nil, errors.New("duplicate string list item rejected")
		}
		seen[text] = struct{}{}
		normalized = append(normalized, text)
	}
	return normalized, nil
}

func validPrintable(text string) bool {
	for _, char := range text {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

// normalizeSectionValues validates a flat section patch supplied by the API and
// returns the canonical section identifier together with the canonical values.
func normalizeSectionValues(index catalogIndex, section string, raw map[string]any) (string, map[string]any, error) {
	canonical, ok := index.canonicalSection(section)
	if !ok {
		return "", nil, fmt.Errorf("%w: unknown settings section", ErrValidation)
	}
	if len(raw) == 0 {
		return "", nil, fmt.Errorf("%w: no settings values supplied", ErrValidation)
	}
	if len(raw) > maxRequestValues {
		return "", nil, fmt.Errorf("%w: too many settings values", ErrValidation)
	}
	normalized := make(map[string]any, len(raw))
	for rawKey, rawValue := range raw {
		key, err := normalizeValueKey(canonical, rawKey)
		if err != nil {
			return "", nil, err
		}
		control, exists := index.sectionControl(canonical, key)
		if !exists {
			return "", nil, fmt.Errorf("%w: unknown control in section %s", ErrValidation, canonical)
		}
		value, err := normalizeControlValue(control, rawValue)
		if err != nil {
			return "", nil, fmt.Errorf("%w: control %s: %v", ErrValidation, control.ID, err)
		}
		normalized[key] = value
	}
	return canonical, normalized, nil
}

func normalizeValueKey(section, rawKey string) (string, error) {
	key := strings.TrimSpace(rawKey)
	if key == "" || len(key) > 96 {
		return "", fmt.Errorf("%w: invalid control key", ErrValidation)
	}
	if !validPrintable(key) {
		return "", fmt.Errorf("%w: invalid control key", ErrValidation)
	}
	if strings.ContainsRune(key, '.') {
		keySection, short := splitControlID(key)
		if !strings.EqualFold(keySection, section) || short == "" {
			return "", fmt.Errorf("%w: control key does not belong to section", ErrValidation)
		}
		return short, nil
	}
	return key, nil
}

// normalizeProfileValues fills the full value document from defaults and the
// provided (validated) overrides.
func normalizeProfileValues(index catalogIndex, raw map[string]map[string]any) (map[string]map[string]any, error) {
	if len(raw) > len(index.sections) {
		return nil, fmt.Errorf("%w: too many settings sections", ErrValidation)
	}
	values := defaultValues()
	for rawSection, rawValues := range raw {
		section, ok := index.canonicalSection(rawSection)
		if !ok {
			return nil, fmt.Errorf("%w: unknown settings section", ErrValidation)
		}
		canonical, normalized, err := normalizeSectionValues(index, section, rawValues)
		if err != nil {
			return nil, err
		}
		for key, value := range normalized {
			values[canonical][key] = value
		}
	}
	return values, nil
}

// validateSectionSemantics enforces cross-field constraints that no single
// control can express.
func validateSectionSemantics(section string, values map[string]map[string]any) error {
	switch section {
	case SectionKinetic:
		minEvents, okEvents := valueInt(values, SectionKinetic, "minEvents")
		minPorts, okPorts := valueInt(values, SectionKinetic, "minDistinctPorts")
		if okEvents && okPorts && minPorts > minEvents {
			return fmt.Errorf("%w: kinetic minDistinctPorts must not exceed minEvents", ErrValidation)
		}
	case SectionFirewall:
		if loggingEnabled, ok := valueBool(values, SectionFirewall, "loggingEnabled"); ok && !loggingEnabled {
			if dropped, droppedOK := valueBool(values, SectionFirewall, "logDroppedPackets"); droppedOK && dropped {
				return fmt.Errorf("%w: dropped packet logging requires firewall logging", ErrValidation)
			}
		}
	}
	return nil
}

func validReason(reason string) error {
	trimmed := strings.TrimSpace(reason)
	if len(trimmed) < minReasonLength || len(trimmed) > maxReasonLength {
		return errors.New("reason boundary rejected")
	}
	if !validPrintable(trimmed) {
		return errors.New("reason contains control characters")
	}
	return nil
}

func normalizeProfileID(id string) (string, error) {
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) < 3 || len(id) > 32 {
		return "", fmt.Errorf("%w: profile id length rejected", ErrValidation)
	}
	for position, char := range id {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
			if position == 0 {
				return "", fmt.Errorf("%w: profile id must start with a letter", ErrValidation)
			}
		case char == '-':
			if position == 0 || position == len(id)-1 {
				return "", fmt.Errorf("%w: profile id must not start or end with a dash", ErrValidation)
			}
		default:
			return "", fmt.Errorf("%w: profile id contains unsupported characters", ErrValidation)
		}
	}
	return id, nil
}

func normalizeProfileName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: profile name required", ErrValidation)
	}
	if utf8.RuneCountInString(name) > maxNameLength {
		return "", fmt.Errorf("%w: profile name too long", ErrValidation)
	}
	if !validPrintable(name) {
		return "", fmt.Errorf("%w: profile name contains control characters", ErrValidation)
	}
	return name, nil
}

func normalizeProfileDescription(description string) (string, error) {
	description = strings.TrimSpace(description)
	if utf8.RuneCountInString(description) > maxDescription {
		return "", fmt.Errorf("%w: profile description too long", ErrValidation)
	}
	if !validPrintable(description) {
		return "", fmt.Errorf("%w: profile description contains control characters", ErrValidation)
	}
	return description, nil
}

func normalizeProfileLevel(level string) (string, error) {
	level = strings.ToLower(strings.TrimSpace(level))
	for _, candidate := range allLevelIDs {
		if level == candidate {
			return level, nil
		}
	}
	return "", fmt.Errorf("%w: unknown protection level", ErrValidation)
}

func controlAvailableAtLevel(control Control, level string) bool {
	for _, candidate := range control.Levels {
		if candidate == level {
			return true
		}
	}
	return false
}

func normalizeHardeningComponents(raw any) (any, error) {
	items, ok := raw.([]string)
	if !ok {
		return nil, errors.New("hardening component list required")
	}
	if len(items) > len(hardeningComponentIDs) {
		return nil, errors.New("hardening component list exceeds catalog")
	}
	selected := make(map[string]struct{}, len(items))
	for _, item := range items {
		if !containsString(hardeningComponentIDs, item) {
			return nil, errors.New("unknown hardening component")
		}
		selected[item] = struct{}{}
	}
	canonical := make([]string, 0, len(items))
	for _, component := range hardeningComponentIDs {
		if _, exists := selected[component]; exists {
			canonical = append(canonical, component)
		}
	}
	return canonical, nil
}

func normalizeProcessNames(raw any) (any, error) {
	items, ok := raw.([]string)
	if !ok {
		return nil, errors.New("process name list required")
	}
	seen := make(map[string]struct{}, len(items))
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		if len(item) > 64 {
			return nil, errors.New("process name too long")
		}
		if strings.ContainsAny(item, `/\:*?"<>|`) {
			return nil, errors.New("process name must be a file name, not a path")
		}
		if item == "." || item == ".." {
			return nil, errors.New("invalid process name")
		}
		lower := strings.ToLower(item)
		if _, duplicate := seen[lower]; duplicate {
			return nil, errors.New("duplicate process name rejected")
		}
		seen[lower] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeAutoDisarm(raw any) (any, error) {
	value, err := integerValue(raw)
	if err != nil {
		return nil, err
	}
	if value == 0 {
		return 0, nil
	}
	if value < 300 || value > 604800 {
		return nil, errors.New("auto disarm must be 0 (disabled) or within 300..604800 seconds")
	}
	return int(value), nil
}

func normalizeASRRules(raw any) (any, error) {
	items, ok := raw.([]string)
	if !ok {
		return nil, errors.New("ASR rule list required")
	}
	type rule struct{ id, action string }
	parsed := make([]rule, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	actions := map[string]struct{}{"block": {}, "audit": {}, "warn": {}, "disabled": {}}
	for _, item := range items {
		identifier, action, cut := strings.Cut(item, ":")
		identifier = strings.ToLower(strings.TrimSpace(identifier))
		action = strings.ToLower(strings.TrimSpace(action))
		if !cut || !validASRRuleID(identifier) {
			return nil, errors.New("ASR rule entries must use the canonical Defender rule UUID")
		}
		if _, valid := actions[action]; !valid {
			return nil, errors.New("unknown ASR rule action")
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, errors.New("duplicate ASR rule rejected")
		}
		seen[identifier] = struct{}{}
		parsed = append(parsed, rule{id: identifier, action: action})
	}
	sort.Slice(parsed, func(left, right int) bool { return parsed[left].id < parsed[right].id })
	normalized := make([]string, 0, len(parsed))
	for _, item := range parsed {
		normalized = append(normalized, item.id+":"+item.action)
	}
	return normalized, nil
}

// validASRRuleID accepts a canonical Defender ASR rule UUID: 36 characters in
// 8-4-4-4-12 hexadecimal form. The settings layer only validates the stable
// identifier format; the Lead-owned applier maps it to the Windows preference.
func validASRRuleID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		switch index {
		case 8, 13, 18, 23:
			if value[index] != '-' {
				return false
			}
		default:
			char := value[index]
			if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
				return false
			}
		}
	}
	return true
}

func normalizeFeedActions(raw any) (any, error) {
	items, ok := raw.([]string)
	if !ok {
		return nil, errors.New("feed action list required")
	}
	actions := map[string]struct{}{"block": {}, "correlate": {}, "annotate": {}}
	selected := make(map[string]string, len(items))
	for _, item := range items {
		feed, action, cut := strings.Cut(item, ":")
		feed = strings.TrimSpace(feed)
		action = strings.ToLower(strings.TrimSpace(action))
		if !cut || !containsString(threatFeedIDs, feed) {
			return nil, errors.New("unknown threat feed key")
		}
		if _, valid := actions[action]; !valid {
			return nil, errors.New("unknown feed action")
		}
		if _, duplicate := selected[feed]; duplicate {
			return nil, errors.New("duplicate feed action rejected")
		}
		selected[feed] = action
	}
	normalized := make([]string, 0, len(selected))
	for _, feed := range threatFeedIDs {
		if action, exists := selected[feed]; exists {
			normalized = append(normalized, feed+":"+action)
		}
	}
	return normalized, nil
}

func normalizeProtectedNetworks(raw any) (any, error) {
	items, ok := raw.([]string)
	if !ok {
		return nil, errors.New("protected network list required")
	}
	seen := make(map[string]struct{}, len(items))
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		prefix, err := parseProtectedNetwork(item)
		if err != nil {
			return nil, err
		}
		canonical := prefix.String()
		if _, duplicate := seen[canonical]; duplicate {
			return nil, errors.New("duplicate protected network rejected")
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func parseProtectedNetwork(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 49 {
		return netip.Prefix{}, errors.New("protected network prefix rejected")
	}
	var prefix netip.Prefix
	if strings.ContainsRune(value, '/') {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, errors.New("protected network prefix rejected")
		}
		prefix = parsed
	} else {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, errors.New("protected network address rejected")
		}
		address = address.Unmap()
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	address := prefix.Addr().Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return netip.Prefix{}, errors.New("protected network must be public unicast")
	}
	minimum := 32
	if address.Is4() {
		minimum = 16
	}
	if prefix.Bits() < minimum {
		return netip.Prefix{}, errors.New("protected network prefix is too broad")
	}
	return prefix.Masked(), nil
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
