// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

func loadSettingsFixture(t *testing.T, name string) SettingsConfig {
	t.Helper()
	config, err := ParseSettingsConfig(readTestFixture(t, name))
	if err != nil {
		t.Fatalf("ParseSettingsConfig(%s) error = %v", name, err)
	}
	return config
}

func TestParseSettingsConfigNormalizesValidFixture(t *testing.T) {
	config := loadSettingsFixture(t, "settings_valid.json")
	if config.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d", config.SchemaVersion)
	}
	if config.Defender == nil || config.Firewall == nil || len(config.Components) != 2 {
		t.Fatalf("sections missing: %+v", config)
	}
	defender := config.Defender
	if defender.CloudBlockLevel == nil || *defender.CloudBlockLevel != "HighPlus" {
		t.Fatalf("CloudBlockLevel = %v", defender.CloudBlockLevel)
	}
	if defender.MAPSReporting == nil || *defender.MAPSReporting != "Advanced" {
		t.Fatalf("MAPSReporting = %v", defender.MAPSReporting)
	}
	if defender.SubmitSamplesConsent == nil || *defender.SubmitSamplesConsent != "SendSafeSamples" {
		t.Fatalf("SubmitSamplesConsent = %v", defender.SubmitSamplesConsent)
	}
	if defender.NetworkProtection == nil || *defender.NetworkProtection != "Enabled" {
		t.Fatalf("NetworkProtection = %v", defender.NetworkProtection)
	}
	if defender.PUAProtection == nil || *defender.PUAProtection != "AuditMode" {
		t.Fatalf("PUAProtection = %v", defender.PUAProtection)
	}
	if defender.ControlledFolderAccess == nil || *defender.ControlledFolderAccess != "AuditMode" {
		t.Fatalf("ControlledFolderAccess = %v", defender.ControlledFolderAccess)
	}
	if len(defender.ASRRules) != 2 {
		t.Fatalf("ASRRules = %+v", defender.ASRRules)
	}
	expectedIDs := []string{"56a863a9-875e-4185-98a7-b882c64b5ce5", "d4f940ab-401b-4efc-aadc-ad5f3c50688a"}
	expectedActions := []string{"Enabled", "AuditMode"}
	for index := range defender.ASRRules {
		if defender.ASRRules[index].ID != expectedIDs[index] || defender.ASRRules[index].Action != expectedActions[index] {
			t.Fatalf("ASR rule %d = %+v", index, defender.ASRRules[index])
		}
	}
	profiles := config.Firewall.Profiles
	if len(profiles) != 1 {
		t.Fatalf("firewall profiles = %+v", profiles)
	}
	profile := profiles[0]
	if profile.Name != "Private" {
		t.Fatalf("profile Name = %q", profile.Name)
	}
	if profile.Enabled == nil || !*profile.Enabled {
		t.Fatalf("profile Enabled = %v", profile.Enabled)
	}
	if profile.DefaultInboundAction == nil || *profile.DefaultInboundAction != "Block" {
		t.Fatalf("profile inbound = %v", profile.DefaultInboundAction)
	}
	if profile.DefaultOutboundAction == nil || *profile.DefaultOutboundAction != "Allow" {
		t.Fatalf("profile outbound = %v", profile.DefaultOutboundAction)
	}
	if profile.NotifyOnListen == nil || !*profile.NotifyOnListen {
		t.Fatalf("profile NotifyOnListen = %v", profile.NotifyOnListen)
	}
	if profile.AllowUnicastResponseToMulticast == nil || *profile.AllowUnicastResponseToMulticast {
		t.Fatalf("profile AllowUnicastResponseToMulticast = %v", profile.AllowUnicastResponseToMulticast)
	}
	if profile.LogBlocked == nil || !*profile.LogBlocked || profile.LogAllowed == nil || *profile.LogAllowed {
		t.Fatalf("profile log flags = %+v", profile)
	}
	if profile.LogMaxSizeKilobytes == nil || *profile.LogMaxSizeKilobytes != 16384 {
		t.Fatalf("profile log size = %v", profile.LogMaxSizeKilobytes)
	}
	if config.Components[0] != "ASR" || config.Components[1] != "Firewall" {
		t.Fatalf("components = %v", config.Components)
	}
}

func TestParseSettingsConfigTreatsNullOptionalsAsUnset(t *testing.T) {
	config := loadSettingsFixture(t, "settings_null_optional.json")
	if config.Defender == nil || config.Firewall != nil || config.Components != nil {
		t.Fatalf("null optional sections were not normalized away: %+v", config)
	}
	if config.Defender.CloudBlockLevel != nil || config.Defender.ASRRules != nil {
		t.Fatalf("null optional fields were not normalized away: %+v", config.Defender)
	}
	if config.Defender.MAPSReporting == nil || *config.Defender.MAPSReporting != "Advanced" {
		t.Fatalf("remaining setting lost: %+v", config.Defender)
	}
}

func TestParseSettingsConfigRejectsInvalidFixtures(t *testing.T) {
	names := []string{
		"settings_unknown_field.json",
		"settings_bad_enum.json",
		"settings_duplicate_asr.json",
		"settings_bad_firewall.json",
		"settings_trailing_data.json",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSettingsConfig(readTestFixture(t, name)); err == nil {
				t.Fatalf("invalid fixture %s was accepted", name)
			}
		})
	}
}

func TestParseSettingsConfigRejectsMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"whitespace":       []byte("   \n\t"),
		"null":             []byte("null"),
		"array":            []byte("[]"),
		"nul_byte":         []byte("{\"schemaVersion\":1,\"components\":[\"ASR\"]}\x00"),
		"schema_missing":   []byte(`{"components":["ASR"]}`),
		"schema_version":   []byte(`{"schemaVersion":2}`),
		"no_settings":      []byte(`{"schemaVersion":1}`),
		"unknown_nested":   []byte(`{"schemaVersion":1,"defender":{"evil":1}}`),
		"trailing_content": []byte(`{"schemaVersion":1,"components":["ASR"]}true`),
		"oversize":         bytes.Repeat([]byte(" "), MaxSettingsConfigBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSettingsConfig(raw); err == nil {
				t.Fatalf("malformed input %q was accepted", name)
			}
		})
	}
}

func TestSettingsConfigValidateStructPaths(t *testing.T) {
	validProfiles := func() *FirewallSettings {
		return &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Private", Enabled: boolPointer(true)}}}
	}
	valid := func() SettingsConfig {
		return SettingsConfig{SchemaVersion: 1, Defender: &DefenderSettings{CloudBlockLevel: stringPointer("High")}}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]SettingsConfig{
		"schema_zero":            {Defender: &DefenderSettings{CloudBlockLevel: stringPointer("High")}},
		"schema_two":             {SchemaVersion: 2, Defender: &DefenderSettings{CloudBlockLevel: stringPointer("High")}},
		"no_sections":            {SchemaVersion: 1},
		"empty_defender":         {SchemaVersion: 1, Defender: &DefenderSettings{}},
		"empty_asr_list":         {SchemaVersion: 1, Defender: &DefenderSettings{ASRRules: []ASRRuleSetting{}}},
		"unknown_asr_rule":       {SchemaVersion: 1, Defender: &DefenderSettings{ASRRules: []ASRRuleSetting{{ID: "11111111-1111-1111-1111-111111111111", Action: "Enabled"}}}},
		"duplicate_asr_rule":     {SchemaVersion: 1, Defender: &DefenderSettings{ASRRules: []ASRRuleSetting{{ID: asrRuleDefinitions[0].ID, Action: "Enabled"}, {ID: strings.ToUpper(asrRuleDefinitions[0].ID), Action: "AuditMode"}}}},
		"bad_asr_action":         {SchemaVersion: 1, Defender: &DefenderSettings{ASRRules: []ASRRuleSetting{{ID: asrRuleDefinitions[0].ID, Action: "Delete"}}}},
		"bad_cloud_level":        {SchemaVersion: 1, Defender: &DefenderSettings{CloudBlockLevel: stringPointer("Ultra")}},
		"bad_sample_consent":     {SchemaVersion: 1, Defender: &DefenderSettings{SubmitSamplesConsent: stringPointer("SendEverything")}},
		"no_firewall_profiles":   {SchemaVersion: 1, Firewall: &FirewallSettings{}},
		"bad_profile_name":       {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Work", Enabled: boolPointer(true)}}}},
		"duplicate_profile":      {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Domain", Enabled: boolPointer(true)}, {Name: "domain", LogBlocked: boolPointer(true)}}}},
		"empty_profile_entry":    {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Domain"}}}},
		"bad_inbound_action":     {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Domain", DefaultInboundAction: stringPointer("Reject")}}}},
		"bad_outbound_action":    {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Domain", DefaultOutboundAction: stringPointer("Drop")}}}},
		"log_size_zero":          {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Domain", LogMaxSizeKilobytes: intPointer(0)}}}},
		"log_size_large":         {SchemaVersion: 1, Firewall: &FirewallSettings{Profiles: []FirewallProfileSetting{{Name: "Domain", LogMaxSizeKilobytes: intPointer(32768)}}}},
		"unknown_component":      {SchemaVersion: 1, Components: []string{"Rootkit"}},
		"duplicate_component":    {SchemaVersion: 1, Components: []string{"ASR", "ASR"}},
		"case_variant_component": {SchemaVersion: 1, Components: []string{"asr"}},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if err := config.Validate(); err == nil {
				t.Fatalf("invalid config %q was accepted: %+v", name, config)
			}
		})
	}
	if err := (SettingsConfig{SchemaVersion: 1, Firewall: validProfiles()}).Validate(); err != nil {
		t.Fatalf("valid firewall config rejected: %v", err)
	}
}

func TestNormalizedSettingsConfigJSONContract(t *testing.T) {
	config := loadSettingsFixture(t, "settings_valid.json")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal normalized config: %v", err)
	}
	expected := `{"schemaVersion":1,` +
		`"defender":{"cloudBlockLevel":"HighPlus","mapsReporting":"Advanced","submitSamplesConsent":"SendSafeSamples","networkProtection":"Enabled","puaProtection":"AuditMode","controlledFolderAccess":"AuditMode","asrRules":[{"id":"56a863a9-875e-4185-98a7-b882c64b5ce5","action":"Enabled"},{"id":"d4f940ab-401b-4efc-aadc-ad5f3c50688a","action":"AuditMode"}]},` +
		`"firewall":{"profiles":[{"name":"Private","enabled":true,"defaultInboundAction":"Block","defaultOutboundAction":"Allow","notifyOnListen":true,"allowUnicastResponseToMulticast":false,"logBlocked":true,"logAllowed":false,"logMaxSizeKilobytes":16384}]},` +
		`"components":["ASR","Firewall"]}`
	if string(raw) != expected {
		t.Fatalf("normalized JSON contract changed:\n got: %s\nwant: %s", raw, expected)
	}
}

func TestApplyReportFixtureDecodes(t *testing.T) {
	result := decodeResultFixture(t, "result_telemetry.json")
	report := result.ApplyReport
	if report == nil {
		t.Fatal("ApplyReport missing")
	}
	if report.SchemaVersion != 1 || report.BaselineState != "existing" || !report.RollbackAvailable {
		t.Fatalf("report summary mismatch: %+v", report)
	}
	if report.ChangedCount != 2 || report.UnchangedCount != 1 {
		t.Fatalf("report counts mismatch: %+v", report)
	}
	if len(report.Entries) != 2 || len(report.Components) != 1 {
		t.Fatalf("report inventory mismatch: %+v", report)
	}
	if report.Entries[0].Before != "High" || report.Entries[0].After != "HighPlus" || !report.Entries[0].Changed {
		t.Fatalf("entry mismatch: %+v", report.Entries[0])
	}
	if report.Entries[1].Changed {
		t.Fatalf("unchanged entry reported changed: %+v", report.Entries[1])
	}
	if report.Components[0].ID != "Firewall" || !report.Components[0].Before || !report.Components[0].After || report.Components[0].Changed {
		t.Fatalf("component entry mismatch: %+v", report.Components[0])
	}
}

func TestApplySettingsRejectsInvalidConfigWithoutStaging(t *testing.T) {
	operationRoot := t.TempDir()
	engine := &Engine{script: filepath.Join(operationRoot, "missing-engine.ps1"), operationRoot: operationRoot}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := engine.ApplySettings(ctx, SettingsConfig{SchemaVersion: 1, Components: []string{"Rootkit"}}); err == nil {
		t.Fatal("invalid settings config was accepted")
	}
	entries, err := os.ReadDir(operationRoot)
	if err != nil {
		t.Fatalf("read operation root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid config staged files: %v", entries)
	}
}

func TestApplySettingsRejectsOversizedDefenderList(t *testing.T) {
	operationRoot := t.TempDir()
	engine := &Engine{script: filepath.Join(operationRoot, "missing-engine.ps1"), operationRoot: operationRoot}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rules := make([]ASRRuleSetting, 0, len(asrRuleDefinitions)+1)
	for _, rule := range asrRuleDefinitions {
		rules = append(rules, ASRRuleSetting{ID: rule.ID, Action: "Enabled"})
	}
	rules = append(rules, ASRRuleSetting{ID: asrRuleDefinitions[0].ID, Action: "Enabled"})
	config := SettingsConfig{SchemaVersion: 1, Defender: &DefenderSettings{ASRRules: rules}}
	if _, err := engine.ApplySettings(ctx, config); err == nil {
		t.Fatal("oversized ASR rule list was accepted")
	}
	entries, err := os.ReadDir(operationRoot)
	if err != nil {
		t.Fatalf("read operation root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected config staged files: %v", entries)
	}
}

func TestApplySettingsFailsClosedAndCleansStaging(t *testing.T) {
	operationRoot := t.TempDir()
	engine := &Engine{script: filepath.Join(operationRoot, "missing-engine.ps1"), operationRoot: operationRoot}
	config := SettingsConfig{SchemaVersion: 1, Defender: &DefenderSettings{CloudBlockLevel: stringPointer("High")}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := engine.ApplySettings(ctx, config); err == nil {
		t.Fatal("apply with unavailable engine reported success")
	}
	entries, err := os.ReadDir(operationRoot)
	if err != nil {
		t.Fatalf("read operation root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging artifacts remained after failed apply: %v", entries)
	}
}

func TestApplySettingsRecordsRejectedEvidence(t *testing.T) {
	directory := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(directory, "evidence.jsonl"), filepath.Join(directory, "evidence.key"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	engine := &Engine{script: filepath.Join(directory, "missing-engine.ps1"), operationRoot: t.TempDir(), ledger: ledger}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := engine.ApplySettings(ctx, SettingsConfig{SchemaVersion: 1, Components: []string{"Rootkit"}}); err == nil {
		t.Fatal("invalid settings config was accepted")
	}
	records, err := ledger.Snapshot(10)
	if err != nil {
		t.Fatalf("snapshot ledger: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ledger records = %+v", records)
	}
	if records[0].Kind != "hardening.settings" || records[0].Result != "rejected" {
		t.Fatalf("rejected apply evidence missing: %+v", records[0])
	}
}
