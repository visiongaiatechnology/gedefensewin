// STATUS: DIAMANT VGT SUPREME
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type recordingApplier struct {
	mu      sync.Mutex
	changes []Change
	err     error
	calls   int
}

func (applier *recordingApplier) Apply(_ context.Context, change Change) error {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	applier.calls++
	applier.changes = append(applier.changes, change)
	return applier.err
}

func (applier *recordingApplier) count() int {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	return applier.calls
}

func (applier *recordingApplier) last() (Change, bool) {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	if len(applier.changes) == 0 {
		return Change{}, false
	}
	return applier.changes[len(applier.changes)-1], true
}

type recordingEvidence struct {
	mu      sync.Mutex
	entries []string
	err     error
}

func (evidence *recordingEvidence) Append(kind, action, result string) error {
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	if evidence.err != nil {
		return evidence.err
	}
	evidence.entries = append(evidence.entries, kind+"|"+action+"|"+result)
	return nil
}

func (evidence *recordingEvidence) count() int {
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	return len(evidence.entries)
}

const (
	validReasonText   = "operator approved settings update"
	validConfirmation = ConfirmationApplySettings
)

func newTestService(t *testing.T) (*Service, string, *recordingApplier) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	applier := &recordingApplier{}
	service, err := OpenWithOptions(Options{Path: path, Applier: applier})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	return service, path, applier
}

func findProfileIn(t *testing.T, profiles []Profile, id string) Profile {
	t.Helper()
	for _, profile := range profiles {
		if profile.ID == id {
			return profile
		}
	}
	t.Fatalf("profile %q not found", id)
	return Profile{}
}

func TestCatalogIsCompleteAndSafe(t *testing.T) {
	catalog := CatalogDefinition()
	if catalog.SchemaVersion != SchemaVersion || catalog.CatalogVersion != CatalogVersion {
		t.Fatalf("unexpected catalog metadata: %+v", catalog)
	}
	if len(catalog.Sections) != 8 {
		t.Fatalf("expected 8 sections, got %d", len(catalog.Sections))
	}
	if len(catalog.Levels) != 4 {
		t.Fatalf("expected 4 levels, got %d", len(catalog.Levels))
	}
	levelIDs := make(map[string]struct{}, len(catalog.Levels))
	for _, level := range catalog.Levels {
		if level.ID == "" || level.Label == "" || level.Description == "" || level.Confirmation == "" {
			t.Fatalf("incomplete level metadata: %+v", level)
		}
		levelIDs[level.ID] = struct{}{}
	}
	for _, required := range []string{LevelMonitor, LevelGuarded, LevelSovereign, LevelCustom} {
		if _, exists := levelIDs[required]; !exists {
			t.Fatalf("missing protection level %q", required)
		}
	}

	requiredControls := []string{
		"defender.realtimeProtection", "defender.behaviorProtection", "defender.cloudBlockLevel",
		"defender.sampleSubmission", "defender.networkProtection", "defender.puaProtection",
		"defender.controlledFolderAccess", "defender.asrRuleActions",
		"firewall.domainProfileEnabled", "firewall.privateProfileEnabled", "firewall.publicProfileEnabled",
		"firewall.defaultInboundAction", "firewall.notificationsEnabled", "firewall.loggingEnabled",
		"hardening.enabledComponents",
		"mhx.aggressiveness", "mhx.autoTerminate", "mhx.applicationControl", "mhx.networkDefaultDeny",
		"kinetic.persistedArmed", "kinetic.burstWindowSeconds", "kinetic.minEvents",
		"kinetic.minDistinctPorts", "kinetic.autoDisarmSeconds",
		"threatIntelligence.pollIntervalSeconds", "threatIntelligence.feedActions",
		"threatIntelligence.protectedNetworks", "threatIntelligence.blockingEnabled",
		"startup.autoStartService", "startup.readinessCheck",
		"notifications.enabled", "notifications.verbosity",
	}
	seen := make(map[string]struct{}, len(catalog.Controls))
	typeCount := make(map[string]int)
	sectionIDs := make(map[string]struct{}, len(catalog.Sections))
	for _, section := range catalog.Sections {
		sectionIDs[section.ID] = struct{}{}
	}
	for _, control := range catalog.Controls {
		if _, duplicate := seen[control.ID]; duplicate {
			t.Fatalf("duplicate control id %q", control.ID)
		}
		seen[control.ID] = struct{}{}
		if _, exists := sectionIDs[control.Section]; !exists {
			t.Fatalf("control %q has unknown section", control.ID)
		}
		section, short := splitControlID(control.ID)
		if section != control.Section || short == "" {
			t.Fatalf("control id/section mismatch: %q/%q", control.ID, control.Section)
		}
		if control.Type == "" || control.Label == "" || control.Description == "" {
			t.Fatalf("incomplete control metadata: %q", control.ID)
		}
		if control.Risk != RiskLow && control.Risk != RiskMedium && control.Risk != RiskHigh && control.Risk != RiskCritical {
			t.Fatalf("invalid risk metadata: %q", control.ID)
		}
		if len(control.Levels) == 0 {
			t.Fatalf("missing level availability: %q", control.ID)
		}
		for _, level := range control.Levels {
			if _, exists := levelIDs[level]; !exists {
				t.Fatalf("control %q has unknown level %q", control.ID, level)
			}
		}
		typeCount[control.Type]++
		if _, err := normalizeControlValue(control, control.Default); err != nil {
			t.Fatalf("default for %q is not valid: %v", control.ID, err)
		}
		switch control.Type {
		case TypeInteger:
			if control.Min == nil || control.Max == nil || *control.Min > *control.Max {
				t.Fatalf("integer bounds missing for %q", control.ID)
			}
			defaultValue, _ := integerValue(control.Default)
			if defaultValue < *control.Min || defaultValue > *control.Max {
				t.Fatalf("default outside bounds for %q", control.ID)
			}
		case TypeEnum:
			if len(control.Options) < 2 {
				t.Fatalf("enum options missing for %q", control.ID)
			}
			if !containsString(control.Options, control.Default.(string)) {
				t.Fatalf("default enum outside options for %q", control.ID)
			}
		}
	}
	for _, required := range requiredControls {
		if _, exists := seen[required]; !exists {
			t.Fatalf("required control missing from catalog: %q", required)
		}
	}
	if typeCount[TypeBool] == 0 || typeCount[TypeInteger] == 0 || typeCount[TypeEnum] == 0 || typeCount[TypeStringList] == 0 {
		t.Fatalf("catalog does not cover all control types: %+v", typeCount)
	}

	encoded, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("catalog marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("catalog unmarshal: %v", err)
	}
	controlsJSON, ok := decoded["controls"].([]any)
	if !ok || len(controlsJSON) != len(catalog.Controls) {
		t.Fatalf("catalog controls JSON shape rejected")
	}
	firstControl, ok := controlsJSON[0].(map[string]any)
	if !ok {
		t.Fatalf("catalog control JSON shape rejected")
	}
	for _, key := range []string{"id", "section", "label", "category", "description", "type", "default", "risk", "requiresRestart", "levels"} {
		if _, exists := firstControl[key]; !exists {
			t.Fatalf("catalog control JSON misses key %q", key)
		}
	}
}

func TestBuiltinProfilesSatisfyLevelFloors(t *testing.T) {
	profiles := builtinProfiles()
	if len(profiles) != 3 {
		t.Fatalf("expected 3 built-in profiles, got %d", len(profiles))
	}
	for _, profile := range profiles {
		if !profile.BuiltIn || profile.ID != profile.Level {
			t.Fatalf("unexpected built-in profile identity: %+v", profile)
		}
		if violations := levelViolations(profile.Level, profile.Values); len(violations) != 0 {
			t.Fatalf("built-in profile %q violates its floor: %v", profile.ID, violations)
		}
		for _, control := range allControls() {
			value, exists := profile.Values[control.Section][shortControlID(control.ID)]
			if !exists {
				t.Fatalf("built-in profile %q misses control %q", profile.ID, control.ID)
			}
			if _, err := normalizeControlValue(control, value); err != nil {
				t.Fatalf("built-in profile %q has invalid value for %q: %v", profile.ID, control.ID, err)
			}
		}
	}
	if _, exists := builtinProfile(DefaultProfileID); !exists {
		t.Fatalf("default profile is not a built-in profile")
	}
}

func TestSnapshotDefaultsWithoutFile(t *testing.T) {
	service, path, _ := newTestService(t)
	snapshot := service.Snapshot()
	if snapshot.State != StateDefaults || snapshot.StateDetail != "" {
		t.Fatalf("unexpected default state: %q/%q", snapshot.State, snapshot.StateDetail)
	}
	if snapshot.ActiveProfileID != DefaultProfileID || snapshot.ActiveLevel != DefaultProfileID || snapshot.ProtectionLevel != DefaultProfileID {
		t.Fatalf("unexpected default active profile: %+v", snapshot)
	}
	if !snapshot.UpdatedUTC.IsZero() {
		t.Fatalf("default snapshot must not claim an update timestamp")
	}
	if snapshot.ProfileDrift {
		t.Fatalf("default snapshot must not report drift")
	}
	if !snapshot.ApplierReady {
		t.Fatalf("wired applier must be reported as ready")
	}
	if snapshot.Schema.Version != SchemaVersion || snapshot.Schema.CatalogVersion != CatalogVersion {
		t.Fatalf("unexpected schema metadata: %+v", snapshot.Schema)
	}
	if !valuesEqual(snapshot.Values, defaultValues()) {
		t.Fatalf("default snapshot values do not match catalog defaults")
	}
	if len(snapshot.Profiles) != 3 || len(snapshot.Levels) != 4 || len(snapshot.Sections) != 8 {
		t.Fatalf("default snapshot misses catalog metadata: %+v", snapshot)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading defaults must not create a settings file: %v", err)
	}
}

func TestApplyPersistsAtomically(t *testing.T) {
	service, path, applier := newTestService(t)
	result, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"sampleSubmission": "always"}, validReasonText, validConfirmation)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.Applied || result.Section != SectionDefender || result.UpdatedUTC.IsZero() {
		t.Fatalf("unexpected apply result: %+v", result)
	}
	if len(result.AppliedControls) != 1 || result.AppliedControls[0] != "defender.sampleSubmission" {
		t.Fatalf("unexpected applied controls: %v", result.AppliedControls)
	}
	snapshot := result.Snapshot
	if snapshot.State != StatePersisted {
		t.Fatalf("expected persisted state, got %q", snapshot.State)
	}
	if snapshot.ActiveProfileID != DefaultProfileID {
		t.Fatalf("a section apply must not change the active profile")
	}
	if !snapshot.ProfileDrift {
		t.Fatalf("edited values must be reported as profile drift")
	}
	change, ok := applier.last()
	if !ok || change.Kind != ChangeSettings || change.Section != SectionDefender {
		t.Fatalf("unexpected applier change: %+v", change)
	}
	if change.ReasonSHA256 == "" || len(change.ReasonSHA256) != 64 {
		t.Fatalf("reason digest missing from applier change")
	}
	if _, exists := change.Sections[SectionDefender]["sampleSubmission"]; !exists {
		t.Fatalf("applier change must carry full next section values")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("persisted document missing: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("persisted document is not JSON: %v", err)
	}
	for _, key := range []string{"schemaVersion", "updatedUtc", "activeProfileId", "profiles", "values"} {
		if _, exists := document[key]; !exists {
			t.Fatalf("persisted document misses key %q", key)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(string(raw)), "}") {
		t.Fatalf("persisted document must end with a complete JSON object")
	}

	reopened, err := OpenWithOptions(Options{Path: path, Applier: &recordingApplier{}})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	restored := reopened.Snapshot()
	if restored.State != StatePersisted {
		t.Fatalf("reopened state = %q (%s)", restored.State, restored.StateDetail)
	}
	if value, _ := valueString(restored.Values, SectionDefender, "sampleSubmission"); value != "always" {
		t.Fatalf("persisted value lost: %q", value)
	}
	if !restored.UpdatedUTC.Equal(snapshot.UpdatedUTC) {
		t.Fatalf("persisted timestamp not restored")
	}
}

func TestApplyValidationBoundaries(t *testing.T) {
	service, path, applier := newTestService(t)
	tooManyProcessNames := make([]any, 0, 65)
	for index := 0; index < 65; index++ {
		tooManyProcessNames = append(tooManyProcessNames, "process"+strings.Repeat("x", index%3)+string(rune('a'+index%26))+".exe")
	}
	cases := []struct {
		name         string
		section      string
		values       map[string]any
		reason       string
		confirmation string
		want         error
	}{
		{"unknown section", "unknownSection", map[string]any{"enabled": true}, validReasonText, validConfirmation, ErrValidation},
		{"unknown control", SectionDefender, map[string]any{"notAControl": true}, validReasonText, validConfirmation, ErrValidation},
		{"wrong type", SectionDefender, map[string]any{"realtimeProtection": "yes"}, validReasonText, validConfirmation, ErrValidation},
		{"out of bounds", SectionFirewall, map[string]any{"logMaxSizeKB": 5}, validReasonText, validConfirmation, ErrValidation},
		{"invalid enum", SectionDefender, map[string]any{"cloudBlockLevel": "extreme"}, validReasonText, validConfirmation, ErrValidation},
		{"empty values", SectionFirewall, map[string]any{}, validReasonText, validConfirmation, ErrValidation},
		{"short reason", SectionDefender, map[string]any{"ioavProtection": false}, "short", validConfirmation, ErrValidation},
		{"control characters in reason", SectionDefender, map[string]any{"ioavProtection": false}, "operator\napproved change", validConfirmation, ErrValidation},
		{"missing confirmation", SectionDefender, map[string]any{"ioavProtection": false}, validReasonText, "", ErrConflict},
		{"wrong section prefix", SectionDefender, map[string]any{"firewall.defaultInboundAction": "allow"}, validReasonText, validConfirmation, ErrValidation},
		{"oversized list", SectionMHX, map[string]any{"restrictedProcessNames": tooManyProcessNames}, validReasonText, validConfirmation, ErrValidation},
		{"invalid asr rule id", SectionDefender, map[string]any{"asrRuleActions": []any{"madeUpRule:block"}}, validReasonText, validConfirmation, ErrValidation},
		{"invalid asr action", SectionDefender, map[string]any{"asrRuleActions": []any{"9e6c4e1f-7d60-472f-ba0a-8f5e6f7a1f9a:panic"}}, validReasonText, validConfirmation, ErrValidation},
		{"invalid protected network", SectionThreatIntelligence, map[string]any{"protectedNetworks": []any{"10.0.0.0/8"}}, validReasonText, validConfirmation, ErrValidation},
		{"invalid feed", SectionThreatIntelligence, map[string]any{"feedActions": []any{"madeUpFeed:block"}}, validReasonText, validConfirmation, ErrValidation},
		{"invalid hardening component", SectionHardening, map[string]any{"enabledComponents": []any{"Bogus"}}, validReasonText, validConfirmation, ErrValidation},
		{"invalid kinetic auto disarm", SectionKinetic, map[string]any{"autoDisarmSeconds": 100}, validReasonText, validConfirmation, ErrValidation},
		{"kinetic cross-field", SectionKinetic, map[string]any{"minEvents": 4, "minDistinctPorts": 8}, validReasonText, validConfirmation, ErrValidation},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.Apply(context.Background(), testCase.section, testCase.values, testCase.reason, testCase.confirmation)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("want %v, got %v", testCase.want, err)
			}
		})
	}
	if applier.count() != 0 {
		t.Fatalf("rejected requests must never reach the applier")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected requests must not create persisted state")
	}
}

func TestApplyProtectionLevelFloor(t *testing.T) {
	service, path, applier := newTestService(t)
	floorCases := []struct {
		name    string
		section string
		values  map[string]any
	}{
		{"disable realtime", SectionDefender, map[string]any{"realtimeProtection": false}},
		{"disable behavior", SectionDefender, map[string]any{"behaviorProtection": false}},
		{"disable network protection", SectionDefender, map[string]any{"networkProtection": false}},
		{"disable pua", SectionDefender, map[string]any{"puaProtection": false}},
		{"disable controlled folder access", SectionDefender, map[string]any{"controlledFolderAccess": false}},
		{"lower cloud level", SectionDefender, map[string]any{"cloudBlockLevel": "default"}},
		{"disable sample submission", SectionDefender, map[string]any{"sampleSubmission": "never"}},
		{"allow inbound", SectionFirewall, map[string]any{"defaultInboundAction": "allow"}},
		{"disable firewall profile", SectionFirewall, map[string]any{"publicProfileEnabled": false}},
		{"disable auto terminate", SectionMHX, map[string]any{"autoTerminate": false}},
		{"drop asr hardening", SectionHardening, map[string]any{"enabledComponents": []any{"Firewall"}}},
		{"downgrade blocking feed", SectionThreatIntelligence, map[string]any{"feedActions": []any{"feodo:correlate"}}},
	}
	for _, testCase := range floorCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.Apply(context.Background(), testCase.section, testCase.values, validReasonText, validConfirmation)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("want ErrConflict, got %v", err)
			}
		})
	}
	if applier.count() != 0 {
		t.Fatalf("floor violations must never reach the applier")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("floor violations must not persist")
	}

	// A non-invariant field may be changed while guarded stays active.
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("non-floor change rejected: %v", err)
	}
	if applier.count() != 1 {
		t.Fatalf("accepted change must reach the applier")
	}
}

func TestApplyWithoutApplierFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	service, err := OpenWithOptions(Options{Path: path})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	_, applyErr := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation)
	if !errors.Is(applyErr, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", applyErr)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unapplied change must not persist")
	}
	if service.Snapshot().State != StateDefaults {
		t.Fatalf("unapplied change must not alter the reported state")
	}
	if service.Snapshot().ApplierReady {
		t.Fatalf("a nil applier must be reported as not ready")
	}
}

func TestApplierFailureDoesNotPersist(t *testing.T) {
	service, path, applier := newTestService(t)
	applier.err = errors.New("engine rejected change")
	_, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation)
	if err == nil {
		t.Fatalf("applier failure must fail the apply")
	}
	if applier.count() != 1 {
		t.Fatalf("applier must be called exactly once")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed applier must not persist state")
	}
	if service.Snapshot().State != StateDefaults {
		t.Fatalf("failed applier must not change the snapshot state")
	}

	applier.err = nil
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("retried apply rejected: %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("successful retry must persist: %v", statErr)
	}
}

func TestPersistenceFailureDoesNotReportSuccess(t *testing.T) {
	service, path, applier := newTestService(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("prepare blocking directory: %v", err)
	}
	_, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation)
	if !errors.Is(err, ErrPersistence) {
		t.Fatalf("want ErrPersistence, got %v", err)
	}
	if applier.count() != 1 {
		t.Fatalf("change was applied before persistence failed")
	}
	snapshot := service.Snapshot()
	if snapshot.State == StatePersisted {
		t.Fatalf("failed persistence must not report persisted success")
	}
	if value, _ := valueBool(snapshot.Values, SectionDefender, "ioavProtection"); !value {
		t.Fatalf("failed persistence must not mutate the reported values")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove blocking directory: %v", err)
	}
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("retry after persistence recovery: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("retry must persist: %v", err)
	}
}

func TestCorruptStateFailsSafe(t *testing.T) {
	validDocument := `{"schemaVersion":1,"updatedUtc":"2026-10-22T10:00:00Z","activeProfileId":"guarded","profiles":[],"values":{}}`
	tamperedDocument := `{"schemaVersion":1,"updatedUtc":"2026-10-22T10:00:00Z","activeProfileId":"guarded","profiles":[],"values":{"defender":{"realtimeProtection":false}}}`
	cases := []struct {
		name    string
		payload string
	}{
		{"invalid json", "{{{not-json"},
		{"unsupported schema", `{"schemaVersion":99,"updatedUtc":"2026-10-22T10:00:00Z","activeProfileId":"guarded","profiles":[],"values":{}}`},
		{"unknown field", `{"schemaVersion":1,"updatedUtc":"2026-10-22T10:00:00Z","activeProfileId":"guarded","profiles":[],"values":{},"unexpected":true}`},
		{"trailing data", validDocument + `{"second":true}`},
		{"missing timestamp", `{"schemaVersion":1,"activeProfileId":"guarded","profiles":[],"values":{}}`},
		{"tampered invariant", tamperedDocument},
		{"unknown active profile", `{"schemaVersion":1,"updatedUtc":"2026-10-22T10:00:00Z","activeProfileId":"ghost","profiles":[],"values":{}}`},
		{"invalid profile", `{"schemaVersion":1,"updatedUtc":"2026-10-22T10:00:00Z","activeProfileId":"guarded","profiles":[{"id":"broken","name":"","level":"custom","builtIn":false,"updatedUtc":"2026-10-22T10:00:00Z","values":{}}],"values":{}}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "settings.json")
			if err := os.WriteFile(path, []byte(testCase.payload), 0o600); err != nil {
				t.Fatalf("write corrupt document: %v", err)
			}
			service, err := OpenWithOptions(Options{Path: path, Applier: &recordingApplier{}})
			if err != nil {
				t.Fatalf("corrupt state must not make Open fail: %v", err)
			}
			snapshot := service.Snapshot()
			if snapshot.State != StateRecovered {
				t.Fatalf("state = %q, want recovered", snapshot.State)
			}
			if snapshot.StateDetail == "" {
				t.Fatalf("recovered state must report a bounded detail code")
			}
			if snapshot.ActiveProfileID != DefaultProfileID || snapshot.ActiveLevel != DefaultProfileID {
				t.Fatalf("recovered state must fail safe to the documented default profile")
			}
			if !valuesEqual(snapshot.Values, defaultValues()) {
				t.Fatalf("recovered state must fail safe to documented defaults")
			}
			if _, statErr := os.Stat(path + ".corrupt"); statErr != nil {
				t.Fatalf("rejected document must be preserved for forensics: %v", statErr)
			}
			// A subsequent accepted change must recover to persisted state.
			if _, applyErr := service.Apply(context.Background(), SectionDefender,
				map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); applyErr != nil {
				t.Fatalf("apply after recovery: %v", applyErr)
			}
			if service.Snapshot().State != StatePersisted {
				t.Fatalf("successful apply must replace the recovered state")
			}
		})
	}
}

func TestProfileLifecycle(t *testing.T) {
	service, path, applier := newTestService(t)
	ctx := context.Background()
	initial := service.Snapshot()
	if len(initial.Profiles) != 3 {
		t.Fatalf("expected 3 built-in profiles, got %d", len(initial.Profiles))
	}

	created, err := service.CreateProfile(ctx, ProfileInput{
		ID:          "lab-profile",
		Name:        "Lab Profile",
		Description: "operator lab profile",
		Level:       LevelCustom,
		Values: map[string]map[string]any{
			SectionDefender: {"sampleSubmission": "always"},
			SectionMHX:      {"minimumConfidence": 75},
		},
	})
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	lab := findProfileIn(t, created.Profiles, "lab-profile")
	if lab.BuiltIn || lab.Level != LevelCustom || lab.UpdatedUTC.IsZero() {
		t.Fatalf("unexpected custom profile: %+v", lab)
	}
	if value, _ := valueString(lab.Values, SectionDefender, "sampleSubmission"); value != "always" {
		t.Fatalf("profile override lost: %q", value)
	}
	if value, _ := valueInt(lab.Values, SectionMHX, "minimumConfidence"); value != 75 {
		t.Fatalf("profile integer override lost: %d", value)
	}
	if value, _ := valueString(lab.Values, SectionFirewall, "defaultInboundAction"); value != "block" {
		t.Fatalf("profile defaults must be inherited: %q", value)
	}

	if _, err := service.CreateProfile(ctx, ProfileInput{ID: "lab-profile", Name: "Duplicate", Level: LevelCustom}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate profile id must be rejected, got %v", err)
	}
	if _, err := service.CreateProfile(ctx, ProfileInput{ID: "Bad_ID", Name: "Bad", Level: LevelCustom}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid profile id must be rejected, got %v", err)
	}
	if _, err := service.CreateProfile(ctx, ProfileInput{ID: "unknown-level", Name: "Bad", Level: "ultimate"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid profile level must be rejected, got %v", err)
	}
	if _, err := service.CreateProfile(ctx, ProfileInput{ID: "bad-values", Name: "Bad", Level: LevelCustom, Values: map[string]map[string]any{SectionDefender: {"noSuchControl": true}}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown profile control must be rejected, got %v", err)
	}
	if _, err := service.CreateProfile(ctx, ProfileInput{
		ID: "weak-guarded", Name: "Weak Guarded", Level: LevelGuarded,
		Values: map[string]map[string]any{SectionDefender: {"realtimeProtection": false}},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("profile weakening a built-in level floor must be rejected, got %v", err)
	}
	if _, err := service.CreateProfile(ctx, ProfileInput{
		ID: "guarded-lab", Name: "Guarded Lab", Level: LevelGuarded,
		Values: map[string]map[string]any{SectionDefender: {"ioavProtection": false}},
	}); err != nil {
		t.Fatalf("guarded profile within its floor rejected: %v", err)
	}
	if _, err := service.CreateProfile(ctx, ProfileInput{ID: "delete-me", Name: "Delete Me", Level: LevelCustom}); err != nil {
		t.Fatalf("create disposable profile: %v", err)
	}

	updated, err := service.UpdateProfile(ctx, "lab-profile", ProfileInput{
		Name: "Lab Profile V2", Description: "updated", Level: LevelCustom,
		Values: map[string]map[string]any{SectionMHX: {"minimumConfidence": 80}},
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	lab = findProfileIn(t, updated.Profiles, "lab-profile")
	if lab.Name != "Lab Profile V2" {
		t.Fatalf("profile update lost the name: %q", lab.Name)
	}
	if value, _ := valueInt(lab.Values, SectionMHX, "minimumConfidence"); value != 80 {
		t.Fatalf("profile update lost the value: %d", value)
	}
	if _, err := service.UpdateProfile(ctx, "guarded", ProfileInput{Name: "Nope", Level: LevelCustom}); !errors.Is(err, ErrConflict) {
		t.Fatalf("built-in profile update must be rejected, got %v", err)
	}
	if _, err := service.UpdateProfile(ctx, "missing-profile", ProfileInput{Name: "Nope", Level: LevelCustom}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown profile update must be rejected, got %v", err)
	}

	if _, err := service.DeleteProfile(ctx, "delete-me"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := service.DeleteProfile(ctx, "delete-me"); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown profile delete must be rejected, got %v", err)
	}
	if _, err := service.DeleteProfile(ctx, LevelGuarded); !errors.Is(err, ErrConflict) {
		t.Fatalf("built-in profile delete must be rejected, got %v", err)
	}

	// Explicit custom activation is required before a custom profile becomes active.
	if _, err := service.ApplyProfile(ctx, "lab-profile", validReasonText, validConfirmation); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong custom confirmation must be rejected, got %v", err)
	}
	if applier.count() != 0 {
		t.Fatalf("rejected profile activation must not reach the applier")
	}
	applied, err := service.ApplyProfile(ctx, "lab-profile", validReasonText, ConfirmationCustom)
	if err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	if applied.ActiveProfileID != "lab-profile" || applied.ActiveLevel != LevelCustom {
		t.Fatalf("custom profile not active: %+v", applied)
	}
	if applied.ProfileDrift {
		t.Fatalf("a fresh profile activation must not report drift")
	}
	change, ok := applier.last()
	if !ok || change.Kind != ChangeProfile || change.ProfileID != "lab-profile" {
		t.Fatalf("unexpected profile applier change: %+v", change)
	}
	if len(change.Changed) == 0 {
		t.Fatalf("profile activation must list changed controls")
	}
	if _, err := service.DeleteProfile(ctx, "lab-profile"); !errors.Is(err, ErrConflict) {
		t.Fatalf("active profile delete must be rejected, got %v", err)
	}

	// Built-in level activation uses its own explicit phrase.
	if _, err := service.ApplyProfile(ctx, LevelSovereign, validReasonText, ConfirmationGuarded); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong level phrase must be rejected, got %v", err)
	}
	sovereign, err := service.ApplyProfile(ctx, LevelSovereign, validReasonText, ConfirmationSovereign)
	if err != nil {
		t.Fatalf("sovereign activation: %v", err)
	}
	if sovereign.ActiveLevel != LevelSovereign {
		t.Fatalf("sovereign level not active")
	}
	if value, _ := valueString(sovereign.Values, SectionDefender, "cloudBlockLevel"); value != "zeroTolerance" {
		t.Fatalf("sovereign baseline values not applied: %q", value)
	}
	if _, err := service.ApplyProfile(ctx, LevelMonitor, validReasonText, ConfirmationMonitor); err != nil {
		t.Fatalf("monitor activation: %v", err)
	}
	// Monitor level keeps the response controls non-configurable.
	if _, err := service.Apply(ctx, SectionMHX, map[string]any{"autoTerminate": false}, validReasonText, validConfirmation); !errors.Is(err, ErrConflict) {
		t.Fatalf("control unavailable at monitor level must be rejected, got %v", err)
	}

	reopened, err := OpenWithOptions(Options{Path: path, Applier: &recordingApplier{}})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	restored := reopened.Snapshot()
	if restored.ActiveProfileID != LevelMonitor {
		t.Fatalf("persisted active profile lost: %q (%s)", restored.ActiveProfileID, restored.StateDetail)
	}
	if len(restored.Profiles) != 5 {
		t.Fatalf("persisted custom profiles lost: %d", len(restored.Profiles))
	}
	findProfileIn(t, restored.Profiles, "guarded-lab")
}

func TestCustomProfileExplicitWeakening(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := context.Background()
	if _, err := service.CreateProfile(ctx, ProfileInput{
		ID: "reduced", Name: "Reduced", Level: LevelCustom,
		Values: map[string]map[string]any{
			SectionDefender: {"realtimeProtection": false, "behaviorProtection": false},
			SectionFirewall: {"defaultInboundAction": "allow"},
		},
	}); err != nil {
		t.Fatalf("custom profile creation must allow explicit weakening: %v", err)
	}
	applied, err := service.ApplyProfile(ctx, "reduced", validReasonText, ConfirmationCustom)
	if err != nil {
		t.Fatalf("custom weakening activation: %v", err)
	}
	if applied.ActiveLevel != LevelCustom {
		t.Fatalf("custom level not active")
	}
	if value, _ := valueBool(applied.Values, SectionDefender, "realtimeProtection"); value {
		t.Fatalf("explicit custom weakening was not persisted")
	}
	if value, _ := valueString(applied.Values, SectionFirewall, "defaultInboundAction"); value != "allow" {
		t.Fatalf("explicit custom firewall weakening was not persisted")
	}
	// The same values can never be smuggled into a guarded profile.
	if _, err := service.CreateProfile(ctx, ProfileInput{
		ID: "sneaky", Name: "Sneaky", Level: LevelGuarded,
		Values: map[string]map[string]any{SectionFirewall: {"defaultInboundAction": "allow"}},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("guarded profile must reject weakening, got %v", err)
	}
}

func TestEvidencePreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	evidence := &recordingEvidence{}
	service, err := OpenWithOptions(Options{Path: path, Applier: &recordingApplier{}, Evidence: evidence})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if evidence.count() != 1 {
		t.Fatalf("expected one evidence preflight record, got %d", evidence.count())
	}
	if !strings.Contains(evidence.entries[0], "reason-sha256=") {
		t.Fatalf("evidence record must only reference the reason digest: %q", evidence.entries[0])
	}
	if strings.Contains(evidence.entries[0], validReasonText) {
		t.Fatalf("evidence record must not store the raw reason text")
	}

	blockedPath := filepath.Join(t.TempDir(), "settings.json")
	blockedEvidence := &recordingEvidence{err: errors.New("ledger unavailable")}
	blockedApplier := &recordingApplier{}
	blocked, err := OpenWithOptions(Options{Path: blockedPath, Applier: blockedApplier, Evidence: blockedEvidence})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	if _, err := blocked.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); !errors.Is(err, ErrPersistence) {
		t.Fatalf("failed evidence preflight must abort the apply, got %v", err)
	}
	if blockedApplier.count() != 0 {
		t.Fatalf("failed evidence preflight must not reach the applier")
	}
	if _, err := os.Stat(blockedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed evidence preflight must not persist")
	}
}

func TestProtectedNetworkValidation(t *testing.T) {
	service, _, _ := newTestService(t)
	invalid := []string{"10.0.0.0/8", "127.0.0.1", "0.0.0.0/0", "8.8.0.0/8", "not-an-address", "169.254.1.1"}
	for _, value := range invalid {
		if _, err := service.Apply(context.Background(), SectionThreatIntelligence,
			map[string]any{"protectedNetworks": []any{value}}, validReasonText, validConfirmation); !errors.Is(err, ErrValidation) {
			t.Fatalf("protected network %q must be rejected, got %v", value, err)
		}
	}
	if _, err := service.Apply(context.Background(), SectionThreatIntelligence,
		map[string]any{"protectedNetworks": []any{"203.0.113.0/24", "198.51.100.7"}}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("valid public protected networks rejected: %v", err)
	}
}

func TestFailurePersistedTimestampNotInvented(t *testing.T) {
	service, path, applier := newTestService(t)
	applier.err = errors.New("simulated engine failure")
	if _, err := service.Apply(context.Background(), SectionNotifications,
		map[string]any{"soundAlerts": true}, validReasonText, validConfirmation); err == nil {
		t.Fatalf("expected applier failure")
	}
	snapshot := service.Snapshot()
	if !snapshot.UpdatedUTC.IsZero() {
		t.Fatalf("failed apply must not invent an update timestamp")
	}
	if snapshot.State != StateDefaults {
		t.Fatalf("failed apply must keep the previous state: %q", snapshot.State)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed apply must not persist a document")
	}
}

func TestPersistedDocumentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not queryable on Windows; ACLs are enforced by the installer")
	}
	service, path, _ := newTestService(t)
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"ioavProtection": false}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted document: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted settings must be 0600, got %o", info.Mode().Perm())
	}
}

func TestConcurrentSnapshotsAndApplies(t *testing.T) {
	service, _, applier := newTestService(t)
	ctx := context.Background()
	var wait sync.WaitGroup
	errs := make(chan error, 64)

	for index := 0; index < 4; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 25; iteration++ {
				snapshot := service.Snapshot()
				if snapshot.SchemaVersion != SchemaVersion {
					errs <- errors.New("snapshot schema version corrupted")
					return
				}
				if value, _ := valueBool(snapshot.Values, SectionDefender, "realtimeProtection"); !value {
					errs <- errors.New("guarded floor missing from snapshot")
					return
				}
			}
		}()
	}

	writers := []struct {
		section string
		values  map[string]any
	}{
		{SectionDefender, map[string]any{"ioavProtection": false}},
		{SectionDefender, map[string]any{"ioavProtection": true}},
		{SectionNotifications, map[string]any{"soundAlerts": true}},
		{SectionNotifications, map[string]any{"soundAlerts": false}},
		{SectionMHX, map[string]any{"minimumConfidence": 55}},
		{SectionMHX, map[string]any{"minimumConfidence": 65}},
		{SectionFirewall, map[string]any{"logMaxSizeKB": 2048}},
		{SectionFirewall, map[string]any{"logMaxSizeKB": 4096}},
	}
	for index := range writers {
		writer := writers[index]
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 6; iteration++ {
				if _, err := service.Apply(ctx, writer.section, writer.values, validReasonText, validConfirmation); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent operation failed: %v", err)
	}
	if applier.count() != 48 {
		t.Fatalf("expected 48 accepted applies, got %d", applier.count())
	}
	if service.Snapshot().State != StatePersisted {
		t.Fatalf("concurrent applies must end in persisted state")
	}
}

func TestASRRuleValidation(t *testing.T) {
	service, _, _ := newTestService(t)
	valid := "9e6c4e1f-7d60-472f-ba0a-8f5e6f7a1f9a"
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"asrRuleActions": []any{strings.ToUpper(valid) + ":block"}}, validReasonText, validConfirmation); err != nil {
		t.Fatalf("valid ASR rule rejected: %v", err)
	}
	rules, _ := valueStringList(service.Snapshot().Values, SectionDefender, "asrRuleActions")
	if len(rules) != 1 || rules[0] != valid+":block" {
		t.Fatalf("ASR rule not canonicalized: %v", rules)
	}
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"asrRuleActions": []any{"not-a-rule-uuid:block"}}, validReasonText, validConfirmation); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid ASR rule must be rejected, got %v", err)
	}
	if _, err := service.Apply(context.Background(), SectionDefender,
		map[string]any{"asrRuleActions": []any{valid + ":block", valid + ":audit"}}, validReasonText, validConfirmation); !errors.Is(err, ErrValidation) {
		t.Fatalf("duplicate ASR rule must be rejected, got %v", err)
	}
}
