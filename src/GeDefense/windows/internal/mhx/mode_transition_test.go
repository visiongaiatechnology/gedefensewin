// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

type fakeProtectionController struct {
	calls         []string
	failMode      string
	kernelEnforce bool
}

func (f *fakeProtectionController) ApplyThreatIntelligence(context.Context, string) (FirewallResult, error) {
	return FirewallResult{}, nil
}
func (f *fakeProtectionController) Applications(context.Context, string, string) (ApplicationAllowResult, error) {
	return ApplicationAllowResult{}, nil
}
func (f *fakeProtectionController) ApplyAppControl(_ context.Context, action string) (AppControlResult, error) {
	f.calls = append(f.calls, "app:"+action)
	switch action {
	case "Enforce":
		f.kernelEnforce = true
		return AppControlResult{Enforced: true, KernelEnforcement: true}, nil
	case "Audit":
		f.kernelEnforce = false
		return AppControlResult{}, nil
	case "Status":
		return AppControlResult{Enforced: f.kernelEnforce, KernelEnforcement: f.kernelEnforce}, nil
	default:
		return AppControlResult{}, errors.New("unexpected app-control action")
	}
}
func (f *fakeProtectionController) Apply(_ context.Context, mode string) (ProtectionResult, error) {
	f.calls = append(f.calls, "mode:"+mode)
	if mode == f.failMode {
		return ProtectionResult{}, errors.New("injected protection failure")
	}
	return ProtectionResult{Mode: mode, DefenderRealtime: true, ProcessTelemetry: true, NetworkDefaultDeny: mode == "sovereign"}, nil
}

func testModeEngine(t *testing.T, controller protectionController, mode string) *Engine {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{root: root, ledger: ledger, protection: controller, mode: mode}
}

func TestSetModeRollsBackPartialSovereignTransition(t *testing.T) {
	controller := &fakeProtectionController{failMode: "sovereign"}
	engine := testModeEngine(t, controller, "guarded")
	if err := engine.SetMode(context.Background(), "sovereign"); err == nil {
		t.Fatal("expected sovereign transition failure")
	}
	if engine.Mode() != "guarded" {
		t.Fatalf("mode changed after failed transition: %q", engine.Mode())
	}
	want := []string{"app:Enforce", "mode:sovereign", "mode:guarded", "app:Audit", "app:Status"}
	if !reflect.DeepEqual(controller.calls, want) {
		t.Fatalf("transition calls = %#v, want %#v", controller.calls, want)
	}
	if engine.kernelEnforcement.Load() {
		t.Fatal("kernel enforcement remained active after rollback")
	}
}

func TestSetModePersistsOnlyAfterVerifiedTransition(t *testing.T) {
	controller := &fakeProtectionController{}
	engine := testModeEngine(t, controller, "guarded")
	if err := engine.SetMode(context.Background(), "sovereign"); err != nil {
		t.Fatalf("SetMode() error: %v", err)
	}
	if engine.Mode() != "sovereign" || !engine.kernelEnforcement.Load() {
		t.Fatal("verified sovereign transition was not committed")
	}
	state, err := loadModeFile(filepath.Join(engine.root, "mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	if state != "sovereign" {
		t.Fatalf("persisted mode = %q", state)
	}
}

func loadModeFile(path string) (string, error) {
	engine := &Engine{root: filepath.Dir(path)}
	if err := engine.loadMode(); err != nil {
		return "", err
	}
	return engine.mode, nil
}

func TestProtectionHealthClearsVerificationTimestampWhenDegraded(t *testing.T) {
	engine := &Engine{}
	engine.setProtectionHealth("VERIFIED")
	if engine.protectionVerifiedUTC.IsZero() {
		t.Fatal("verified protection health did not record verification time")
	}
	engine.setProtectionHealth("DEGRADED")
	if !engine.protectionVerifiedUTC.IsZero() {
		t.Fatal("degraded protection retained stale verification timestamp")
	}
}

type applicationProtectionController struct {
	appResult AppControlResult
	appErr    error
}

func (f *applicationProtectionController) ApplyThreatIntelligence(context.Context, string) (FirewallResult, error) {
	return FirewallResult{}, nil
}
func (f *applicationProtectionController) Applications(_ context.Context, action, path string) (ApplicationAllowResult, error) {
	if action != "Add" || path == "" {
		return ApplicationAllowResult{}, errors.New("unexpected application transaction")
	}
	return ApplicationAllowResult{Entries: []ApplicationAllow{{Path: path}}, Count: 1}, nil
}
func (f *applicationProtectionController) ApplyAppControl(context.Context, string) (AppControlResult, error) {
	return f.appResult, f.appErr
}
func (f *applicationProtectionController) Apply(context.Context, string) (ProtectionResult, error) {
	return ProtectionResult{}, nil
}

func TestSetApplicationDegradesWhenSovereignKernelVerificationFails(t *testing.T) {
	controller := &applicationProtectionController{appResult: AppControlResult{Enforced: true, KernelEnforcement: false}}
	engine := testModeEngine(t, controller, "sovereign")
	engine.setProtectionHealth("VERIFIED")

	if _, err := engine.SetApplication(context.Background(), "Add", `C:\\Program Files\\VGT\\tool.exe`); err == nil {
		t.Fatal("expected application policy verification failure")
	}
	if got := engine.Status().ProtectionHealth; got != "DEGRADED" {
		t.Fatalf("protection health = %q, want DEGRADED", got)
	}
	if engine.kernelEnforcement.Load() {
		t.Fatal("kernel enforcement flag was enabled without verified kernel enforcement")
	}
}

func TestSetApplicationKeepsVerifiedHealthAfterVerifiedSovereignRefresh(t *testing.T) {
	controller := &applicationProtectionController{appResult: AppControlResult{Enforced: true, KernelEnforcement: true}}
	engine := testModeEngine(t, controller, "sovereign")
	engine.setProtectionHealth("VERIFIED")

	if _, err := engine.SetApplication(context.Background(), "Add", `C:\\Program Files\\VGT\\tool.exe`); err != nil {
		t.Fatalf("SetApplication() error: %v", err)
	}
	if got := engine.Status().ProtectionHealth; got != "VERIFIED" {
		t.Fatalf("protection health = %q, want VERIFIED", got)
	}
	if !engine.kernelEnforcement.Load() {
		t.Fatal("verified sovereign refresh did not update kernel enforcement state")
	}
}
