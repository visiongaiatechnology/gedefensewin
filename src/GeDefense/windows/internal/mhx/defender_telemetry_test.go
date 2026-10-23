// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func defenderTelemetryFixture(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
  "collectedUtc": "2026-10-22T08:00:00.0000000Z",
  "computerStatus": {
    "amServiceEnabled": true,
    "amServiceVersion": "4.18.26010.5",
    "amEngineVersion": "1.1.26010.5",
    "amProductVersion": "4.18.26010.5",
    "amRunningMode": "Normal",
    "antivirusEnabled": true,
    "antispywareEnabled": true,
    "behaviorMonitorEnabled": true,
    "ioavProtectionEnabled": true,
    "onAccessProtectionEnabled": false,
    "realTimeProtectionEnabled": true,
    "nisEnabled": true,
    "isTamperProtected": true,
    "isVirtualMachine": false,
    "defenderSignaturesOutOfDate": false,
    "tamperProtectionSource": "Signature",
    "antivirusSignatureVersion": "1.429.1.0",
    "antispywareSignatureVersion": "1.429.1.0",
    "nisSignatureVersion": "1.429.1.0",
    "nisEngineVersion": "1.1.26010.5",
    "antivirusSignatureLastUpdated": "2026-10-22T06:11:12Z",
    "antispywareSignatureLastUpdated": "2026-10-22T06:11:12Z",
    "nisSignatureLastUpdated": "2026-10-22T06:11:12Z",
    "antivirusSignatureAge": 0,
    "antispywareSignatureAge": 0,
    "nisSignatureAge": 0,
    "quickScanAge": 1,
    "fullScanAge": 30,
    "quickScanStartTime": "2026-10-21T18:00:00Z",
    "quickScanEndTime": "2026-10-21T18:10:00Z",
    "fullScanStartTime": "2026-09-22T18:00:00Z",
    "fullScanEndTime": "2026-09-22T19:00:00Z",
    "computerState": 0
  },
  "preferences": {
    "disableRealtimeMonitoring": false,
    "disableBehaviorMonitoring": false,
    "disableIOAVProtection": false,
    "disableScriptScanning": false,
    "disableBlockAtFirstSeen": false,
    "disableArchiveScanning": false,
    "disableEmailScanning": null,
    "disableRemovableDriveScanning": true,
    "disableScanningNetworkFiles": false,
    "enableNetworkProtection": 1,
    "puaProtection": 1,
    "mapsReporting": 2,
    "submitSamplesConsent": 1,
    "cloudBlockLevel": 4,
    "cloudExtendedTimeout": 50,
    "enableControlledFolderAccess": 0,
    "signatureUpdateInterval": 4,
    "checkForSignaturesBeforeRunningScan": false,
    "scanParameters": 1,
    "scanAvgCPULoadFactor": 50,
    "lowThreatDefaultAction": 2,
    "moderateThreatDefaultAction": 2,
    "highThreatDefaultAction": 2,
    "severeThreatDefaultAction": 2,
    "unknownThreatDefaultAction": 2,
    "attackSurfaceReductionRules": [
      {"id": "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "action": 1},
      {"id": "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "action": null}
    ],
    "attackSurfaceReductionOnlyExclusionsCount": 2,
    "exclusionPathCount": 3,
    "exclusionExtensionCount": 1,
    "exclusionProcessCount": null,
    "controlledFolderAccessProtectedFoldersCount": 5,
    "controlledFolderAccessAllowedApplicationsCount": 0
  }
}`)
}

func TestParseDefenderTelemetryKeepsMissingValuesExplicit(t *testing.T) {
	snapshot, err := parseDefenderTelemetry(defenderTelemetryFixture(t))
	if err != nil {
		t.Fatalf("defender telemetry fixture rejected: %v", err)
	}
	if !snapshot.Available || !snapshot.Verified || snapshot.Source != "Get-MpComputerStatus/Get-MpPreference" {
		t.Fatalf("verified snapshot state is wrong: %+v", snapshot)
	}
	if !snapshot.SourceTimestampUTC.Valid || !snapshot.SourceTimestampUTC.Time.Equal(time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("source timestamp not preserved: %+v", snapshot.SourceTimestampUTC)
	}
	status := snapshot.ComputerStatus
	if status == nil || status.RealTimeProtectionEnabled == nil || !*status.RealTimeProtectionEnabled || status.ComputerState == nil || *status.ComputerState != 0 {
		t.Fatalf("computer status values lost: %+v", status)
	}
	if status.AntivirusSignatureLastUpdated.Valid == false {
		t.Fatal("signature timestamp was dropped")
	}
	preferences := snapshot.Preferences
	if preferences == nil || preferences.PUAProtection == nil || *preferences.PUAProtection != 1 || preferences.CloudBlockLevel == nil || *preferences.CloudBlockLevel != 4 {
		t.Fatalf("preference values lost: %+v", preferences)
	}
	if len(preferences.AttackSurfaceReductionRules) != 2 || preferences.AttackSurfaceReductionRules[0].Action == nil || *preferences.AttackSurfaceReductionRules[0].Action != 1 {
		t.Fatalf("ASR rules lost: %+v", preferences.AttackSurfaceReductionRules)
	}
	if preferences.AttackSurfaceReductionRules[1].Action != nil {
		t.Fatal("an unavailable ASR action was invented")
	}
	unavailable := strings.Join(snapshot.UnavailableFields, ",")
	if !strings.Contains(unavailable, "preferences.disableEmailScanning") || !strings.Contains(unavailable, "preferences.exclusionProcessCount") {
		t.Fatalf("explicit unavailable fields are incomplete: %v", snapshot.UnavailableFields)
	}
	// Exclusions must be counts only; the API contract has no path array.
	if strings.Contains(unavailable, "ExclusionPath\"") {
		t.Fatalf("exclusion paths leaked into the telemetry contract: %v", snapshot.UnavailableFields)
	}
}

func TestParseDefenderTelemetryRejectsMalformedPayloads(t *testing.T) {
	cases := map[string][]byte{
		"empty":                {},
		"not-json":             []byte("nope"),
		"missing-timestamp":    []byte(`{"computerStatus":null,"preferences":null}`),
		"bad-timestamp":        []byte(`{"collectedUtc":"yesterday","computerStatus":null,"preferences":null}`),
		"unknown-field":        []byte(`{"collectedUtc":"2026-10-22T08:00:00Z","computerStatus":{"unknownField":true},"preferences":null}`),
		"trailing":             []byte(`{"collectedUtc":"2026-10-22T08:00:00Z","computerStatus":null,"preferences":null} {}`),
		"oversized":            []byte(strings.Repeat("x", maximumDefenderTelemetryBytes+1)),
		"wrong-timestamp-type": []byte(`{"collectedUtc":42,"computerStatus":null,"preferences":null}`),
	}
	for name, payload := range cases {
		if _, err := parseDefenderTelemetry(payload); err == nil {
			t.Fatalf("malformed defender telemetry accepted (%s)", name)
		}
	}
}

func TestParseDefenderTelemetryPartialSourcesAreUnavailableNotInvented(t *testing.T) {
	payload := []byte(`{"collectedUtc":"2026-10-22T08:00:00Z","computerStatus":{"antivirusEnabled":true},"preferences":null}`)
	snapshot, err := parseDefenderTelemetry(payload)
	if err != nil {
		t.Fatalf("partial payload rejected at parse level: %v", err)
	}
	if snapshot.Available || snapshot.Verified || snapshot.Error == "" {
		t.Fatalf("partial source was reported as verified telemetry: %+v", snapshot)
	}
	if snapshot.ComputerStatus.RealTimeProtectionEnabled != nil {
		t.Fatal("missing realtime protection value was fabricated")
	}
	unavailable := strings.Join(snapshot.UnavailableFields, ",")
	if !strings.Contains(unavailable, "computerStatus.realTimeProtectionEnabled") || !strings.Contains(unavailable, "preferences") {
		t.Fatalf("unavailable fields are incomplete: %v", snapshot.UnavailableFields)
	}
}

func TestEngineDefenderTelemetryCachesAndFailsExplicitly(t *testing.T) {
	parsed, err := parseDefenderTelemetry(defenderTelemetryFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	probeCalls := 0
	engine := &Engine{defenderProbe: func(context.Context) (DefenderTelemetry, error) {
		probeCalls++
		return parsed, nil
	}}
	ctx := context.Background()
	first, err := engine.DefenderTelemetry(ctx)
	if err != nil {
		t.Fatalf("defender telemetry probe failed: %v", err)
	}
	if !first.Available || !first.Verified || first.Cached {
		t.Fatalf("fresh snapshot state wrong: %+v", first)
	}
	second, err := engine.DefenderTelemetry(ctx)
	if err != nil || !second.Cached || probeCalls != 1 {
		t.Fatalf("defender telemetry was not cached: calls=%d err=%v", probeCalls, err)
	}
	engine.defenderMu.Lock()
	engine.defenderCacheAt = time.Now().Add(-defenderSuccessTTL - time.Second)
	engine.defenderMu.Unlock()
	if _, err := engine.DefenderTelemetry(ctx); err != nil || probeCalls != 2 {
		t.Fatalf("expired defender cache was not refreshed: calls=%d err=%v", probeCalls, err)
	}
	if status := engine.Status(); status.DefenderTelemetry == nil || !status.DefenderTelemetry.Available {
		t.Fatalf("status did not expose the cached defender snapshot: %+v", status.DefenderTelemetry)
	}
	if _, err := engine.DefenderTelemetry(nil); err == nil {
		t.Fatal("nil context accepted for defender telemetry")
	}
}

func TestEngineDefenderTelemetryProbeFailureIsUnavailableSnapshot(t *testing.T) {
	probeCalls := 0
	engine := &Engine{defenderProbe: func(context.Context) (DefenderTelemetry, error) {
		probeCalls++
		return DefenderTelemetry{}, errors.New("defender telemetry query failed")
	}}
	snapshot, err := engine.DefenderTelemetry(context.Background())
	if err != nil {
		t.Fatalf("probe failure must be reported as data, not error: %v", err)
	}
	if snapshot.Available || snapshot.Verified || snapshot.Source != "UNAVAILABLE" || snapshot.Error == "" {
		t.Fatalf("probe failure snapshot is misleading: %+v", snapshot)
	}
	if _, err := engine.DefenderTelemetry(context.Background()); err != nil || probeCalls != 1 {
		t.Fatalf("failure snapshot was not cached: calls=%d err=%v", probeCalls, err)
	}
	engine.defenderMu.Lock()
	if engine.defenderCacheAt.IsZero() {
		engine.defenderMu.Unlock()
		t.Fatal("failure snapshot timestamp missing")
	}
	engine.defenderMu.Unlock()
}
