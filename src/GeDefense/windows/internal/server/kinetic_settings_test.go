// STATUS: DIAMANT VGT SUPREME
package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

type kineticSettingsTestMHX struct {
	*fixedMHX
	snapshot mhx.KineticSettingsSnapshot
}

func (f *kineticSettingsTestMHX) KineticSettings() mhx.KineticSettingsSnapshot {
	return f.snapshot
}

func (f *kineticSettingsTestMHX) SetKineticConfig(_ context.Context, config kinetic.Config) (mhx.KineticSettingsSnapshot, error) {
	if err := config.Validate(); err != nil {
		return f.snapshot, err
	}
	f.snapshot.Config = config
	f.snapshot.Persisted = true
	return f.snapshot, nil
}

func (f *kineticSettingsTestMHX) SetKineticDesiredState(_ context.Context, armed bool) (mhx.KineticSettingsSnapshot, error) {
	f.snapshot.DesiredArmed = armed
	f.snapshot.Armed = armed
	return f.snapshot, nil
}

func newKineticSettingsTestServer(t *testing.T) (http.Handler, *kineticSettingsTestMHX) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	config := kinetic.DefaultConfig()
	config.AutoDisarmSeconds = kinetic.MinAutoDisarmSeconds
	mhxEngine := &kineticSettingsTestMHX{
		fixedMHX: &fixedMHX{mode: "guarded", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		snapshot: mhx.KineticSettingsSnapshot{
			SchemaVersion: 1,
			Armed:         true,
			DesiredArmed:  true,
			Config:        config,
			Defaults:      kinetic.DefaultConfig(),
			Limits:        config.Limits(),
			Persisted:     true,
		},
	}
	handler := New("test", "01234567890123456789012345678901", fixedEngine{result: hardening.Result{Defender: true}}, fixedAudit{result: audit.Result{Checks: []audit.Check{}}}, fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}}, mhxEngine, &fixedIntegrity{}, ledger)
	return handler, mhxEngine
}

func postKineticSettings(t *testing.T, handler http.Handler, body string, requestNumber int) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/kinetic/settings", bytes.NewBufferString(body))
	request.Host = "127.0.0.1:17831"
	request.RemoteAddr = "127.0.0.1:49152"
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGT-Request-ID", fmt.Sprintf("aaaaaaaa-bbbb-4ccc-8ddd-%012d", requestNumber))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestKineticSettingsAcceptsMinDistinctPortsAndDisablesAutoDisarm(t *testing.T) {
	handler, engine := newKineticSettingsTestServer(t)
	response := postKineticSettings(t, handler, `{"thresholds":{"windowSeconds":20,"minEvents":8,"minDistinctPorts":4},"autoDisarmMinutes":0,"reason":"operator changed kinetic thresholds"}`, 1)
	if response.Code != http.StatusOK {
		t.Fatalf("got %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	config := engine.snapshot.Config
	if config.BurstWindowSeconds != 20 || config.MinEvents != 8 || config.MinDistinctPorts != 4 {
		t.Fatalf("unexpected thresholds stored: %+v", config)
	}
	if config.AutoDisarmSeconds != kinetic.AutoDisarmDisabled {
		t.Fatalf("auto-disarm = %d, want explicit disabled value %d", config.AutoDisarmSeconds, kinetic.AutoDisarmDisabled)
	}
}

func TestKineticSettingsStillAcceptsPortsArray(t *testing.T) {
	handler, engine := newKineticSettingsTestServer(t)
	response := postKineticSettings(t, handler, `{"thresholds":{"windowSeconds":10,"minEvents":12,"ports":[80,443,8080]},"reason":"operator changed kinetic thresholds"}`, 2)
	if response.Code != http.StatusOK {
		t.Fatalf("got %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if engine.snapshot.Config.MinDistinctPorts != 3 {
		t.Fatalf("minDistinctPorts = %d, want 3", engine.snapshot.Config.MinDistinctPorts)
	}
}

func TestKineticSettingsRejectsAmbiguousPortDiversity(t *testing.T) {
	handler, _ := newKineticSettingsTestServer(t)
	response := postKineticSettings(t, handler, `{"thresholds":{"windowSeconds":10,"minEvents":12,"minDistinctPorts":4,"ports":[80,443,8080]},"reason":"operator changed kinetic thresholds"}`, 3)
	if response.Code != http.StatusConflict {
		t.Fatalf("got %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
}
