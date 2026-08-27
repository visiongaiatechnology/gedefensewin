// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
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
}

type FirewallResult struct {
	TimestampUTC string `json:"TimestampUtc"`
	Indicators   int    `json:"Indicators"`
	Rules        int    `json:"Rules"`
	Generation   string `json:"Generation"`
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

type protectionManager struct {
	runner     *scriptengine.Engine
	firewall   *scriptengine.Engine
	allows     *scriptengine.Engine
	appControl *scriptengine.Engine
}

func newProtectionManager(script, firewallScript, allowScript, appControlScript, operations string) (*protectionManager, error) {
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
	appControl, err := scriptengine.New(appControlScript, operations, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return &protectionManager{runner: runner, firewall: firewall, allows: allows, appControl: appControl}, nil
}

func (m *protectionManager) ApplyThreatIntelligence(ctx context.Context, path string) (FirewallResult, error) {
	return scriptengine.RunJSON[FirewallResult](m.firewall, ctx, "mhx-firewall", "-IndicatorPath", path)
}

func (m *protectionManager) Applications(ctx context.Context, action, path string) (ApplicationAllowResult, error) {
	arguments := []string{"-Action", action}
	if path != "" {
		arguments = append(arguments, "-ApplicationPath", path)
	}
	return scriptengine.RunJSON[ApplicationAllowResult](m.allows, ctx, "mhx-app-allow", arguments...)
}

func (m *protectionManager) ApplyAppControl(ctx context.Context, action string) (AppControlResult, error) {
	return scriptengine.RunJSON[AppControlResult](m.appControl, ctx, "mhx-appcontrol", "-Action", action)
}

func (m *protectionManager) Apply(ctx context.Context, mode string) (ProtectionResult, error) {
	name := "Guarded"
	if mode == "monitor" {
		name = "Monitor"
	} else if mode == "sovereign" {
		name = "Sovereign"
	}
	return scriptengine.RunJSON[ProtectionResult](m.runner, ctx, "mhx-mode", "-Mode", name)
}
