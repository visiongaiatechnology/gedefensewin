// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/scriptengine"
)

type ProtectionResult struct {
	TimestampUTC           string `json:"TimestampUtc"`
	Mode                   string `json:"Mode"`
	DefenderRealtime       bool   `json:"DefenderRealtime"`
	NetworkDefaultDeny     bool   `json:"NetworkDefaultDeny"`
	ScriptObfuscationBlock bool   `json:"ScriptObfuscationBlock"`
	ProcessTelemetry       bool   `json:"ProcessTelemetry"`
	WfpBlockTelemetry      bool   `json:"WfpBlockTelemetry"`
}

type FirewallResult struct {
	TimestampUTC         string `json:"TimestampUtc"`
	Indicators           int    `json:"Indicators"`
	Rules                int    `json:"Rules"`
	Shards               int    `json:"Shards"`
	Generation           string `json:"Generation"`
	Mode                 string `json:"Mode"`
	CleanupPending       bool   `json:"CleanupPending"`
	ProtectionGeneration string `json:"ProtectionGeneration"`
	ProtectedPrefixCount int    `json:"ProtectedPrefixCount"`
}

type ApplicationAllow struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Signer   string `json:"signer"`
	AddedUTC string `json:"addedUtc"`
	Rule     string `json:"rule"`
}

type ApplicationAllowResult struct {
	TimestampUTC string             `json:"TimestampUtc"`
	Entries      []ApplicationAllow `json:"Entries"`
	Count        int                `json:"Count"`
}

type AppControlResult struct {
	TimestampUTC      string `json:"TimestampUtc"`
	State             string `json:"State"`
	PolicyID          string `json:"PolicyId"`
	Enforced          bool   `json:"Enforced"`
	KernelEnforcement bool   `json:"KernelEnforcement"`
}

// ApplicationDeny is a real Windows Firewall program rule that blocks both
// directions for one operator-selected executable. It is independent of the
// Authenticode allow list: a deny rule is a strict network kill switch for that
// binary and takes precedence over allow rules in Windows Firewall.
type ApplicationDeny struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	AddedUTC string `json:"addedUtc"`
	Rule     string `json:"rule"`
}

type ApplicationDenyResult struct {
	TimestampUTC string            `json:"TimestampUtc"`
	Entries      []ApplicationDeny `json:"Entries"`
	Count        int               `json:"Count"`
	RuleGroup    string            `json:"RuleGroup"`
	Enforced     bool              `json:"Enforced"`
}

type protectionController interface {
	ApplyThreatIntelligence(context.Context, string, string, int) (FirewallResult, error)
	Applications(context.Context, string, string) (ApplicationAllowResult, error)
	ApplyAppControl(context.Context, string) (AppControlResult, error)
	Apply(context.Context, string) (ProtectionResult, error)
}

type protectionManager struct {
	runner     *scriptengine.Engine
	firewall   *scriptengine.Engine
	allows     *scriptengine.Engine
	denies     *scriptengine.Engine
	appControl *scriptengine.Engine
}

func newProtectionManager(script, firewallScript, allowScript, denyScript, appControlScript, operations string) (*protectionManager, error) {
	runner, err := scriptengine.New(script, operations, 3*time.Minute)
	if err != nil {
		return nil, err
	}
	firewall, err := scriptengine.New(firewallScript, operations, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	allows, err := scriptengine.New(allowScript, operations, 3*time.Minute)
	if err != nil {
		return nil, err
	}
	denies, err := scriptengine.New(denyScript, operations, 3*time.Minute)
	if err != nil {
		return nil, err
	}
	appControl, err := scriptengine.New(appControlScript, operations, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return &protectionManager{runner: runner, firewall: firewall, allows: allows, denies: denies, appControl: appControl}, nil
}

func (m *protectionManager) ApplyThreatIntelligence(ctx context.Context, path, generation string, indicators int) (FirewallResult, error) {
	return scriptengine.RunJSON[FirewallResult](m.firewall, ctx, "mhx-firewall", "-IndicatorPath", path, "-ExpectedGeneration", generation, "-ExpectedIndicators", fmt.Sprintf("%d", indicators))
}

func (m *protectionManager) Applications(ctx context.Context, action, path string) (ApplicationAllowResult, error) {
	arguments := []string{"-Action", action}
	if path != "" {
		arguments = append(arguments, "-ApplicationPath", path)
	}
	return scriptengine.RunJSON[ApplicationAllowResult](m.allows, ctx, "mhx-app-allow", arguments...)
}

func (m *protectionManager) ApplicationDenies(ctx context.Context, action, path string) (ApplicationDenyResult, error) {
	arguments := []string{"-Action", action}
	if path != "" {
		arguments = append(arguments, "-ApplicationPath", path)
	}
	return scriptengine.RunJSON[ApplicationDenyResult](m.denies, ctx, "mhx-app-deny", arguments...)
}

func (m *protectionManager) ApplyAppControl(ctx context.Context, action string) (AppControlResult, error) {
	return scriptengine.RunJSON[AppControlResult](m.appControl, ctx, "mhx-appcontrol", "-Action", action)
}

func (m *protectionManager) Apply(ctx context.Context, mode string) (ProtectionResult, error) {
	name := "Guarded"
	switch mode {
	case "monitor":
		name = "Monitor"
	case "sovereign":
		name = "Sovereign"
	}
	return scriptengine.RunJSON[ProtectionResult](m.runner, ctx, "mhx-mode", "-Mode", name)
}
