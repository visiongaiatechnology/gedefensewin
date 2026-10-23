// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func boolPointer(value bool) *bool       { return &value }
func intPointer(value int) *int          { return &value }
func stringPointer(value string) *string { return &value }

func readTestFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func decodeResultFixture(t *testing.T, name string) Result {
	t.Helper()
	var result Result
	if err := json.Unmarshal(readTestFixture(t, name), &result); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return result
}

func TestLegacyResultDecodesWithoutTelemetry(t *testing.T) {
	result := decodeResultFixture(t, "result_legacy.json")
	if result.ComputerName != "LEGACY-NODE" {
		t.Fatalf("ComputerName = %q", result.ComputerName)
	}
	if !result.Defender || !result.RealTimeProtection || !result.Firewall {
		t.Fatalf("legacy fields lost: %+v", result)
	}
	if result.DefenderTelemetry != nil {
		t.Fatalf("legacy payload must not invent telemetry: %+v", result.DefenderTelemetry)
	}
	if result.ApplyReport != nil {
		t.Fatalf("legacy payload must not invent an apply report: %+v", result.ApplyReport)
	}
}

func TestTelemetryFixtureDecodesMeasuredValues(t *testing.T) {
	result := decodeResultFixture(t, "result_telemetry.json")
	telemetry := result.DefenderTelemetry
	if telemetry == nil {
		t.Fatal("DefenderTelemetry was not decoded")
	}
	if !telemetry.Available || !telemetry.ComputerStatusAvailable || !telemetry.PreferenceAvailable || !telemetry.FirewallAvailable {
		t.Fatalf("availability flags lost: %+v", telemetry)
	}
	if telemetry.ThreatQueryAvailable {
		t.Fatal("unavailable threat query reported as available")
	}
	if len(telemetry.SourcesAttempted) != 5 {
		t.Fatalf("SourcesAttempted = %v", telemetry.SourcesAttempted)
	}
	if telemetry.CapturedUTC != "2026-10-22T08:00:00.0000000Z" {
		t.Fatalf("CapturedUTC = %q", telemetry.CapturedUTC)
	}
	status := telemetry.Status
	if status == nil {
		t.Fatal("Status section missing")
	}
	if status.RealTimeProtectionEnabled == nil || !*status.RealTimeProtectionEnabled {
		t.Fatalf("RealTimeProtectionEnabled = %v", status.RealTimeProtectionEnabled)
	}
	if status.IsTamperProtected == nil || !*status.IsTamperProtected {
		t.Fatalf("IsTamperProtected = %v", status.IsTamperProtected)
	}
	if status.OnAccessProtectionEnabled != nil {
		t.Fatalf("explicit null was fabricated: %v", *status.OnAccessProtectionEnabled)
	}
	if status.AntivirusSignatureAge == nil || *status.AntivirusSignatureAge != 1 {
		t.Fatalf("AntivirusSignatureAge = %v", status.AntivirusSignatureAge)
	}
	if status.AntivirusSignatureVersion == nil || *status.AntivirusSignatureVersion != "1.461.119.0" {
		t.Fatalf("AntivirusSignatureVersion = %v", status.AntivirusSignatureVersion)
	}
	if status.FullScanAge != nil {
		t.Fatalf("explicit null FullScanAge was fabricated: %v", *status.FullScanAge)
	}

	preference := telemetry.Preference
	if preference == nil {
		t.Fatal("Preference section missing")
	}
	if preference.CloudBlockLevel == nil || *preference.CloudBlockLevel != "High" || preference.CloudBlockLevelRaw == nil || *preference.CloudBlockLevelRaw != 2 {
		t.Fatalf("cloud block level mismatch: %+v", preference)
	}
	if preference.SubmitSamplesConsent == nil || *preference.SubmitSamplesConsent != "SendSafeSamples" {
		t.Fatalf("sample consent mismatch: %+v", preference)
	}
	if preference.NetworkProtection == nil || *preference.NetworkProtection != "Enabled" {
		t.Fatalf("network protection mismatch: %+v", preference)
	}
	if preference.ControlledFolderAccessRaw == nil || *preference.ControlledFolderAccessRaw != 2 {
		t.Fatalf("controlled folder access raw mismatch: %+v", preference)
	}

	asr := telemetry.AttackSurfaceReduction
	if asr == nil || !asr.Available {
		t.Fatalf("ASR section missing: %+v", asr)
	}
	if asr.ConfiguredCount != 2 || asr.EnabledCount != 1 || asr.AuditCount != 1 || asr.WarnCount != 0 {
		t.Fatalf("ASR counts mismatch: %+v", asr)
	}
	if len(asr.Rules) != 2 || len(asr.RecommendedMissing) != 1 {
		t.Fatalf("ASR rule inventory mismatch: %+v", asr)
	}
	if asr.Rules[0].Configured != true || asr.Rules[0].Action == nil || *asr.Rules[0].Action != 1 || *asr.Rules[0].ActionName != "Enabled" {
		t.Fatalf("configured ASR rule mismatch: %+v", asr.Rules[0])
	}
	if asr.Rules[1].Configured || asr.Rules[1].Action != nil || asr.Rules[1].ActionName != nil {
		t.Fatalf("unconfigured ASR rule fabricated an action: %+v", asr.Rules[1])
	}

	exclusions := telemetry.Exclusions
	if exclusions == nil || exclusions.Available {
		t.Fatalf("exclusions availability mismatch: %+v", exclusions)
	}
	if exclusions.PathCount != nil || exclusions.ProcessCount != nil || exclusions.ExtensionCount != nil || exclusions.IPAddressCount != nil {
		t.Fatalf("unavailable exclusions reported counts: %+v", exclusions)
	}
	if len(exclusions.Extensions) != 0 || exclusions.ExtensionsTruncated {
		t.Fatalf("unavailable exclusions reported values: %+v", exclusions)
	}

	threats := telemetry.Threats
	if threats == nil || !threats.Available || !threats.DetectionQueryAvailable || threats.ThreatQueryAvailable {
		t.Fatalf("threat availability mismatch: %+v", threats)
	}
	if threats.DetectionCount == nil || *threats.DetectionCount != 5 || threats.ActiveThreatCount != nil {
		t.Fatalf("threat counts mismatch: %+v", threats)
	}
	if threats.LatestDetectionUTC == nil || *threats.LatestDetectionUTC != "2026-10-12T19:01:09.0730000Z" {
		t.Fatalf("latest detection mismatch: %+v", threats)
	}

	firewall := telemetry.Firewall
	if firewall == nil || !firewall.Available || firewall.ProfileCount != 3 || firewall.EnabledProfileCount != 2 {
		t.Fatalf("firewall summary mismatch: %+v", firewall)
	}
	if len(firewall.Profiles) != 3 {
		t.Fatalf("firewall profile count = %d", len(firewall.Profiles))
	}
	if firewall.Profiles[0].Name != "Domain" || firewall.Profiles[0].Enabled == nil || !*firewall.Profiles[0].Enabled || *firewall.Profiles[0].DefaultInboundAction != "Block" {
		t.Fatalf("domain profile mismatch: %+v", firewall.Profiles[0])
	}
	if firewall.Profiles[1].NotifyOnListen != nil {
		t.Fatalf("null firewall field fabricated: %+v", firewall.Profiles[1])
	}
	if firewall.Profiles[2].Enabled == nil || *firewall.Profiles[2].Enabled {
		t.Fatalf("public profile enabled mismatch: %+v", firewall.Profiles[2])
	}
}

func TestTelemetryUnavailableSectionsRemainNil(t *testing.T) {
	raw := []byte(`{"ComputerName":"NO-DEFENDER","DefenderTelemetry":{"Available":false,"ComputerStatusAvailable":false,"PreferenceAvailable":false,"ThreatDetectionAvailable":false,"ThreatQueryAvailable":false,"FirewallAvailable":false,"Status":null,"Preference":null,"AttackSurfaceReduction":null,"Exclusions":null,"Threats":null,"Firewall":null}}`)
	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode unavailable telemetry: %v", err)
	}
	telemetry := result.DefenderTelemetry
	if telemetry == nil {
		t.Fatal("availability object must decode")
	}
	if telemetry.Available {
		t.Fatal("unavailable telemetry reported available")
	}
	if telemetry.Status != nil || telemetry.Preference != nil || telemetry.AttackSurfaceReduction != nil || telemetry.Exclusions != nil || telemetry.Firewall != nil {
		t.Fatalf("unavailable sections fabricated: %+v", telemetry)
	}
	if result.Defender {
		t.Fatal("unavailable telemetry fabricated a Defender boolean")
	}
}

func TestResultTelemetryRoundTrip(t *testing.T) {
	original := decodeResultFixture(t, "result_telemetry.json")
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded Result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if decoded.DefenderTelemetry == nil || decoded.DefenderTelemetry.Preference == nil {
		t.Fatal("telemetry lost in round trip")
	}
	if decoded.DefenderTelemetry.Preference.CloudBlockLevelRaw == nil || *decoded.DefenderTelemetry.Preference.CloudBlockLevelRaw != 2 {
		t.Fatalf("telemetry raw value lost in round trip: %+v", decoded.DefenderTelemetry.Preference)
	}
	if decoded.ApplyReport == nil || decoded.ApplyReport.ChangedCount != 2 {
		t.Fatalf("apply report lost in round trip: %+v", decoded.ApplyReport)
	}
	if decoded.ApplyReport.Entries[0].Before != "High" {
		t.Fatalf("apply report before value = %#v", decoded.ApplyReport.Entries[0].Before)
	}
}

func TestReadBoundedResultRejectsUnsafeSizes(t *testing.T) {
	directory := t.TempDir()
	valid := readTestFixture(t, "result_legacy.json")
	validPath := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(validPath, valid, 0o600); err != nil {
		t.Fatalf("write valid result: %v", err)
	}
	decoded, err := readBoundedResult(validPath)
	if err != nil || decoded.ComputerName != "LEGACY-NODE" {
		t.Fatalf("readBoundedResult(valid) = %+v, %v", decoded, err)
	}
	bomPath := filepath.Join(directory, "bom.json")
	if err := os.WriteFile(bomPath, append([]byte{0xef, 0xbb, 0xbf}, valid...), 0o600); err != nil {
		t.Fatalf("write BOM result: %v", err)
	}
	decoded, err = readBoundedResult(bomPath)
	if err != nil || decoded.ComputerName != "LEGACY-NODE" {
		t.Fatalf("readBoundedResult(BOM) = %+v, %v", decoded, err)
	}
	emptyPath := filepath.Join(directory, "empty.json")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatalf("write empty result: %v", err)
	}
	if _, err := readBoundedResult(emptyPath); err == nil {
		t.Fatal("empty result must be rejected")
	}
	oversizePath := filepath.Join(directory, "oversize.json")
	oversize := append(append([]byte("{\"ComputerName\":\""), []byte(strings.Repeat("A", maxHardeningResultBytes))...), []byte("\"}")...)
	if err := os.WriteFile(oversizePath, oversize, 0o600); err != nil {
		t.Fatalf("write oversize result: %v", err)
	}
	if _, err := readBoundedResult(oversizePath); err == nil {
		t.Fatal("oversize result must be rejected")
	}
}

func TestDefenderTelemetryReadOnlyMethodUsesCachedSnapshot(t *testing.T) {
	expected := &DefenderTelemetry{Available: true, ComputerStatusAvailable: true}
	engine := &Engine{cached: Result{DefenderTelemetry: expected}, cachedAt: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	telemetry, err := engine.DefenderTelemetry(ctx)
	if err != nil {
		t.Fatalf("DefenderTelemetry() error = %v", err)
	}
	if telemetry != expected {
		t.Fatalf("DefenderTelemetry() = %+v, want cached snapshot", telemetry)
	}
}

func TestDefenderTelemetryReadOnlyMethodNeverInventsSnapshot(t *testing.T) {
	engine := &Engine{cached: Result{Defender: true}, cachedAt: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	telemetry, err := engine.DefenderTelemetry(ctx)
	if err != nil {
		t.Fatalf("DefenderTelemetry() error = %v", err)
	}
	if telemetry != nil {
		t.Fatalf("Telemetry was fabricated without a measured snapshot: %+v", telemetry)
	}
}
