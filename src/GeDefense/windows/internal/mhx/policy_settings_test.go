// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
)

func newPolicyTestEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{root: root, ledger: ledger, mode: "guarded", kineticMonitor: kinetic.NewMonitor(), intelligenceWake: make(chan struct{}, 1)}
	engine.loadPolicySettings()
	return engine, root
}

func policyTestEncodedCommand(payload string) string {
	units := utf16.Encode([]rune(payload))
	raw := make([]byte, len(units)*2)
	for index, unit := range units {
		raw[index*2] = byte(unit)
		raw[index*2+1] = byte(unit >> 8)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestPolicySettingsDefaultsExposeOnlyEnforceablePrimitives(t *testing.T) {
	engine, _ := newPolicyTestEngine(t)
	settings := engine.PolicySettings()
	if settings.Aggressiveness != "guarded" || settings.AggressivenessSource != "PROTECTION_MODE" || settings.AggressivenessDefault != "guarded" {
		t.Fatalf("aggressiveness projection is wrong: %+v", settings)
	}
	if !settings.AutoResponse.TerminateProcess || !settings.AutoResponse.CorrelatedNetworkResponse || settings.AutoResponse.MinimumSeverity != SeverityLow {
		t.Fatalf("auto-response defaults do not preserve historical behaviour: %+v", settings.AutoResponse)
	}
	if !settings.Notifications.EventFeedEnabled || !settings.Notifications.KineticEvents || settings.Notifications.MinimumSeverity != SeverityLow {
		t.Fatalf("notification defaults are wrong: %+v", settings.Notifications)
	}
	if settings.Network.DefaultDenyOutbound || settings.Network.EnforcedBy == "" {
		t.Fatalf("guarded mode must not claim default-deny enforcement: %+v", settings.Network)
	}
	if settings.Application.AllowListEnforced || !settings.Application.DenyListSupported || settings.Application.EnforcedBy == "" {
		t.Fatalf("application enforcement capability is misreported: %+v", settings.Application)
	}
	if settings.Process.Supported || settings.Process.Reason == "" {
		t.Fatalf("process restriction capability is misreported: %+v", settings.Process)
	}
	if settings.Source != settingsSourceDefault {
		t.Fatalf("default settings source is wrong: %+v", settings)
	}
}

func TestSetPolicySettingsPersistsSupportedToggles(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{root: root, ledger: ledger, mode: "guarded", kineticMonitor: kinetic.NewMonitor()}
	engine.loadPolicySettings()
	ctx := context.Background()
	patch := PolicySettingsPatch{
		AutoResponse:  &AutoResponseSettings{TerminateProcess: false, CorrelatedNetworkResponse: false, MinimumSeverity: SeverityHigh},
		Notifications: &NotificationSettings{EventFeedEnabled: true, BlockEvents: false, DefenderEvents: true, ThreatIntelEvents: false, KineticEvents: true, MinimumSeverity: SeverityCritical, WindowsToasts: true, ToastMinimumSeverity: SeverityLow},
	}
	updated, err := engine.SetPolicySettings(ctx, patch)
	if err != nil {
		t.Fatalf("supported settings rejected: %v", err)
	}
	if updated.AutoResponse != *patch.AutoResponse || updated.Notifications != *patch.Notifications {
		t.Fatalf("effective settings differ from the accepted patch: %+v", updated)
	}
	if updated.Source != settingsSourcePersisted || updated.UpdatedUTC.IsZero() {
		t.Fatalf("settings were not reported as persisted: %+v", updated)
	}
	if _, statErr := os.Stat(filepath.Join(root, policySettingsFileName)); statErr != nil {
		t.Fatalf("settings file missing: %v", statErr)
	}

	// Restart: the persisted writable policy is restored, while the read-only
	// sections are re-derived from the verified protection mode.
	restartedLedger, err := evidence.Open(filepath.Join(root, "restarted-evidence.jsonl"), filepath.Join(root, "restarted-evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Engine{root: root, ledger: restartedLedger, mode: "sovereign", kineticMonitor: kinetic.NewMonitor()}
	restarted.loadPolicySettings()
	restored := restarted.PolicySettings()
	if restored.AutoResponse != *patch.AutoResponse || restored.Notifications != *patch.Notifications || restored.Source != settingsSourcePersisted {
		t.Fatalf("persisted settings did not survive restart: %+v", restored)
	}
	if restored.Aggressiveness != "sovereign" || !restored.Network.DefaultDenyOutbound || !restored.Application.AllowListEnforced {
		t.Fatalf("read-only sections were not derived from the restarted protection mode: %+v", restored)
	}
}

func TestSetPolicySettingsRejectsUnenforceableFieldsWithoutSideEffects(t *testing.T) {
	engine, root := newPolicyTestEngine(t)
	before := engine.PolicySettings()
	minimumSeverity := "SUPER"
	trueValue := true
	patches := []PolicySettingsPatch{
		{Process: &ProcessPolicyPatch{BlockedCommands: []string{"cmd.exe /c whoami"}}},
		{Application: &ApplicationPolicyPatch{DenyList: []string{`C:\Program Files\bad.exe`}}},
		{ApplicationNetworkRestrictions: &ApplicationNetworkRestrictionsPatch{UnknownPolicy: "block"}},
		{ApplicationNetworkRestrictions: &ApplicationNetworkRestrictionsPatch{AppControlMode: "enforce"}},
		{AutoResponse: &AutoResponseSettings{TerminateProcess: true, MinimumSeverity: Severity(minimumSeverity)}},
		{Notifications: &NotificationSettings{EventFeedEnabled: true, MinimumSeverity: Severity(minimumSeverity)}},
		{Network: &NetworkPolicyPatch{DefaultDenyOutbound: &trueValue}},
		{AggressivenessDomains: &AggressivenessDomainsPatch{Process: stringPointer("monitor"), Network: stringPointer("guarded")}},
		{AggressivenessDomains: &AggressivenessDomainsPatch{}},
		{Aggressiveness: stringPointer("turbo")},
		{Aggressiveness: stringPointer("guarded"), AggressivenessDomains: &AggressivenessDomainsPatch{Process: stringPointer("guarded")}},
	}
	for index, patch := range patches {
		if _, err := engine.SetPolicySettings(context.Background(), patch); err == nil {
			t.Fatalf("patch %d with unenforceable/invalid settings was accepted", index)
		} else {
			var rejected *SettingsRejectedError
			if !errors.As(err, &rejected) || len(rejected.Rejections) == 0 {
				t.Fatalf("patch %d did not return structured rejections: %v", index, err)
			}
		}
		if got := engine.PolicySettings(); got.AutoResponse != before.AutoResponse || got.Notifications != before.Notifications || got.Source != before.Source {
			t.Fatalf("rejected patch %d mutated settings: %+v", index, got)
		}
	}
	if _, statErr := os.Stat(filepath.Join(root, policySettingsFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected settings were persisted: %v", statErr)
	}
}

func TestSetPolicySettingsCollapsesIdenticalPerDomainAggressiveness(t *testing.T) {
	controller := &fakeProtectionController{}
	engine := testModeEngine(t, controller, "monitor")
	engine.loadPolicySettings()
	updated, err := engine.SetPolicySettings(context.Background(), PolicySettingsPatch{
		AggressivenessDomains: &AggressivenessDomainsPatch{
			Process:     stringPointer("guarded"),
			Network:     stringPointer("guarded"),
			Application: stringPointer("guarded"),
		},
	})
	if err != nil {
		t.Fatalf("identical per-domain aggressiveness rejected: %v", err)
	}
	if updated.Aggressiveness != "guarded" || len(updated.Warnings) == 0 {
		t.Fatalf("collapsed profile was not reported honestly: %+v", updated)
	}
	if engine.Mode() != "guarded" {
		t.Fatalf("verified mode transition did not run: %q", engine.Mode())
	}
}

func TestSetPolicySettingsAllowListValidationAndVerifiedApply(t *testing.T) {
	controller := &fakeProtectionController{}
	engine := testModeEngine(t, controller, "guarded")
	engine.loadPolicySettings()
	ctx := context.Background()
	for _, allowList := range [][]string{
		{`relative\tool.exe`},
		{`C:\Program Files\VGT\tool.txt`},
		{`C:\Program Files\VGT\..\escape.exe`},
		{`C:\Program Files\VGT\tool.exe`, `C:\a.exe`, `C:\b.exe`, `C:\c.exe`, `C:\d.exe`, `C:\e.exe`, `C:\f.exe`, `C:\g.exe`, `C:\h.exe`},
	} {
		if _, err := engine.SetPolicySettings(ctx, PolicySettingsPatch{Application: &ApplicationPolicyPatch{AllowList: allowList}}); err == nil {
			t.Fatalf("invalid application allow list accepted: %#v", allowList)
		}
	}
	if _, err := engine.SetPolicySettings(ctx, PolicySettingsPatch{Application: &ApplicationPolicyPatch{AllowList: []string{`C:\Program Files\VGT\ge-tool.exe`}}}); err != nil {
		t.Fatalf("valid application allow list rejected: %v", err)
	}
	found := false
	for _, call := range controller.calls {
		if call == "app:Audit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("verified application apply path was not used: %#v", controller.calls)
	}
}

func TestAutoResponsePolicyGatesTerminationAndNotificationsAreReal(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	terminations := 0
	engine := &Engine{root: root, ledger: ledger, mode: "guarded", kineticMonitor: kinetic.NewMonitor(), recentProcesses: make(map[uint32]recentProcess, 8), terminate: func(ProcessEvent) error {
		terminations++
		return nil
	}}
	engine.loadPolicySettings()
	now := time.Now().UTC()
	blockingEvent := func(pid uint32, payload string) ProcessEvent {
		return ProcessEvent{TimestampUTC: now, PID: pid, Image: "powershell.exe", ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: "powershell.exe -NoLogo -EncodedCommand " + policyTestEncodedCommand(payload)}
	}
	highPayload := `Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))`
	criticalPayload := `Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x))); [AmsiUtils]::ScanBuffer($y)`

	engine.evaluate(blockingEvent(1001, highPayload))
	if terminations != 1 {
		t.Fatalf("default policy did not terminate an authorized high-severity detection: %d", terminations)
	}
	notifications := engine.Notifications(10)
	if len(notifications) != 1 || notifications[0].Kind != notificationKindBlock || notifications[0].Severity != SeverityHigh {
		t.Fatalf("real blocking event did not reach the notification feed: %+v", notifications)
	}

	if _, err := engine.SetPolicySettings(context.Background(), PolicySettingsPatch{AutoResponse: &AutoResponseSettings{TerminateProcess: false, CorrelatedNetworkResponse: true, MinimumSeverity: SeverityLow}}); err != nil {
		t.Fatal(err)
	}
	engine.evaluate(blockingEvent(1002, highPayload))
	if terminations != 1 {
		t.Fatalf("terminateProcess=false did not gate host response: %d", terminations)
	}

	if _, err := engine.SetPolicySettings(context.Background(), PolicySettingsPatch{AutoResponse: &AutoResponseSettings{TerminateProcess: true, CorrelatedNetworkResponse: true, MinimumSeverity: SeverityCritical}}); err != nil {
		t.Fatal(err)
	}
	engine.evaluate(blockingEvent(1003, highPayload))
	if terminations != 1 {
		t.Fatalf("severity floor CRITICAL did not block a HIGH response: %d", terminations)
	}
	engine.evaluate(blockingEvent(1004, criticalPayload))
	if terminations != 2 {
		t.Fatalf("critical detection was not terminated at the CRITICAL floor: %d", terminations)
	}

	if _, err := engine.SetPolicySettings(context.Background(), PolicySettingsPatch{Notifications: &NotificationSettings{EventFeedEnabled: false, BlockEvents: true, DefenderEvents: true, ThreatIntelEvents: true, KineticEvents: true, MinimumSeverity: SeverityLow, WindowsToasts: true, ToastMinimumSeverity: SeverityLow}}); err != nil {
		t.Fatal(err)
	}
	before := len(engine.Notifications(50))
	engine.evaluate(blockingEvent(1005, highPayload))
	if got := len(engine.Notifications(50)); got != before {
		t.Fatalf("disabled notification feed still recorded events: %d -> %d", before, got)
	}

	if _, err := engine.SetPolicySettings(context.Background(), PolicySettingsPatch{Notifications: &NotificationSettings{EventFeedEnabled: true, BlockEvents: false, DefenderEvents: true, ThreatIntelEvents: true, KineticEvents: true, MinimumSeverity: SeverityLow, WindowsToasts: true, ToastMinimumSeverity: SeverityLow}}); err != nil {
		t.Fatal(err)
	}
	before = len(engine.Notifications(50))
	engine.evaluate(blockingEvent(1006, highPayload))
	if got := len(engine.Notifications(50)); got != before {
		t.Fatalf("disabled block-event notification class still recorded events: %d -> %d", before, got)
	}
	if len(engine.Notifications(10000)) > maximumNotificationEntries {
		t.Fatal("notification limit was not bounded")
	}
}

func TestInvalidPersistedPolicySettingsFallBackToDefaults(t *testing.T) {
	invalid := []string{
		"not-json",
		`{"schemaVersion":1,"autoResponse":{"terminateProcess":false,"correlatedNetworkResponse":true,"minimumSeverity":"SUPER"},"notifications":{"eventFeedEnabled":true,"blockEvents":true,"defenderEvents":true,"threatIntelEvents":true,"kineticEvents":true,"minimumSeverity":"LOW"},"updatedUtc":"2026-10-22T08:00:00Z"}`,
		`{"schemaVersion":1,"autoResponse":{"terminateProcess":false,"correlatedNetworkResponse":true,"minimumSeverity":"LOW"},"notifications":{"eventFeedEnabled":true,"blockEvents":true,"defenderEvents":true,"threatIntelEvents":true,"kineticEvents":true,"minimumSeverity":"LOW"},"updatedUtc":"2026-10-22T08:00:00Z","unknown":1}`,
		strings.Repeat("x", maximumPolicySettingsBytes+1),
	}
	for _, body := range invalid {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, policySettingsFileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
		if err != nil {
			t.Fatal(err)
		}
		engine := &Engine{root: root, ledger: ledger, mode: "guarded", kineticMonitor: kinetic.NewMonitor()}
		engine.loadPolicySettings()
		settings := engine.PolicySettings()
		if settings.Source != settingsSourceInvalid || len(settings.Warnings) == 0 {
			t.Fatalf("invalid persisted settings were trusted: %+v", settings)
		}
		if settings.AutoResponse != DefaultAutoResponseSettings() || settings.Notifications != DefaultNotificationSettings() {
			t.Fatalf("invalid persisted settings did not fall back to defaults: %+v", settings)
		}
	}
}

func TestPolicySettingsStatusProjection(t *testing.T) {
	engine, _ := newPolicyTestEngine(t)
	status := engine.Status()
	if status.PolicySettings.Aggressiveness != "guarded" || status.PolicySettings.Process.Supported {
		t.Fatalf("status did not project the effective policy settings: %+v", status.PolicySettings)
	}
	// This engine has no feed manager. Status must not fabricate a polling
	// policy or a kinetic settings snapshot in that case.
	if status.ThreatIntelPolling.IntervalSeconds != 0 || status.ThreatIntelPolling.Source != "" {
		t.Fatalf("status fabricated a threat intelligence polling interval without a manager: %+v", status.ThreatIntelPolling)
	}
	if status.KineticSettings.Config != kinetic.DefaultConfig() || status.KineticSettings.Armed || !status.KineticSettings.Observe {
		t.Fatalf("status kinetic projection is not fail-safe: %+v", status.KineticSettings)
	}
	if status.DefenderTelemetry != nil {
		t.Fatalf("status fabricated defender telemetry without a probe: %+v", status.DefenderTelemetry)
	}
}

func stringPointer(value string) *string { return &value }
