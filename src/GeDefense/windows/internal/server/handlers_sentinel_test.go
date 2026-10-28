// STATUS: DIAMANT VGT SUPREME
package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/titan"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

func newSentinelTestServer(t *testing.T) (http.Handler, *titan.Engine, *mhx.SentinelStore) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	titanEngine, err := titan.New(filepath.Join(root, "titan"), "5.3.0", ledger)
	if err != nil {
		t.Fatal(err)
	}
	sentinelStore, err := mhx.OpenSentinelStore(root)
	if err != nil {
		t.Fatal(err)
	}

	mhxMock := &fixedMHX{
		mode:          "guarded",
		status:        mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"},
		sentinelStore: sentinelStore,
	}

	handler := NewWithTitan("5.3.0", "01234567890123456789012345678901",
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		mhxMock,
		&fixedIntegrity{}, ledger, nil, nil, titanEngine)

	t.Cleanup(func() { _ = titanEngine.Close() })
	return handler, titanEngine, sentinelStore
}

func TestSentinelStatusRequiresAuth(t *testing.T) {
	handler, _, _ := newSentinelTestServer(t)
	req, resp := titanRequest(http.MethodGet, "/api/v1/sentinel/status", "", false)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", resp.Code)
	}
}

func TestSentinelStatusWhenUnavailable(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	// mhxMock without sentinelStore
	mhxMock := &fixedMHX{
		mode:   "guarded",
		status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"},
	}
	handler := NewWithTitan("5.3.0", "01234567890123456789012345678901",
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		mhxMock,
		&fixedIntegrity{}, ledger, nil, nil, nil)

	req, resp := titanRequest(http.MethodGet, "/api/v1/sentinel/status", "", true)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 unavailable, got %d", resp.Code)
	}
}

func TestSentinelStatusSuccess(t *testing.T) {
	handler, titanEngine, _ := newSentinelTestServer(t)
	req, resp := titanRequest(http.MethodGet, "/api/v1/sentinel/status", "", true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s", resp.Code, resp.Body.String())
	}

	var status map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}

	if status["killerdomEnabled"] != true {
		t.Fatalf("expected killerdomEnabled=true, got %v", status["killerdomEnabled"])
	}
	if status["paranoiaMode"] != false {
		t.Fatalf("expected paranoiaMode=false, got %v", status["paranoiaMode"])
	}

	sigs, ok := status["signatures"].([]any)
	if !ok || len(sigs) < 4 {
		t.Fatalf("expected signatures list, got %v", status["signatures"])
	}
	for _, raw := range sigs {
		sig, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("signature entry is not an object: %v", raw)
		}
		pattern, _ := sig["pattern"].(string)
		if strings.TrimSpace(pattern) == "" {
			t.Fatalf("signature %v has no pattern; Sentinel UI renders sig.pattern and would crash", sig["id"])
		}
	}

	// The Sentinel switch must mirror the effective Titan policy.
	if got, want := status["correlateWithTitan"], titanEngine.Policy().CorrelateWithKillerdom; got != want {
		t.Fatalf("correlateWithTitan=%v, Titan policy=%v: Sentinel UI and engine state diverged", got, want)
	}

	sysApps, ok := status["systemApps"].([]any)
	if !ok || len(sysApps) == 0 {
		t.Fatalf("expected systemApps list, got %v", status["systemApps"])
	}

	whitelist, ok := status["whitelist"].([]any)
	if !ok || len(whitelist) == 0 {
		t.Fatalf("expected whitelist list, got %v", status["whitelist"])
	}
}

func TestSentinelUpdateConfigAndTitanSync(t *testing.T) {
	handler, titanEngine, _ := newSentinelTestServer(t)

	body := `{"paranoiaMode": true, "killerdomEnabled": true, "correlateWithTitan": true, "ghostModeTelemetryKill": false, "reason": "Test activation"}`
	req, resp := titanRequest(http.MethodPost, "/api/v1/sentinel/config", body, true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}

	var status map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}

	if status["paranoiaMode"] != true {
		t.Errorf("expected paranoiaMode=true, got %v", status["paranoiaMode"])
	}
	if status["ghostModeTelemetryKill"] != false {
		t.Errorf("expected ghostModeTelemetryKill=false, got %v", status["ghostModeTelemetryKill"])
	}
	if status["correlateWithTitan"] != true {
		t.Errorf("expected correlateWithTitan=true, got %v", status["correlateWithTitan"])
	}

	// Verify Titan engine was synced
	tp := titanEngine.Policy()
	if !tp.CorrelateWithKillerdom {
		t.Errorf("expected Titan policy CorrelateWithKillerdom to be true, got %v", tp.CorrelateWithKillerdom)
	}
}

func TestSentinelToggleSignature(t *testing.T) {
	handler, _, _ := newSentinelTestServer(t)

	// Disabling a signature reduces coverage and must require a typed
	// confirmation plus an operator reason.
	unauthorized := `{"sigId": "KD-SIG-01", "enabled": false}`
	req, resp := titanRequest(http.MethodPost, "/api/v1/sentinel/signatures/toggle", unauthorized, true)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409 for unconfirmed signature downgrade, got %d body=%s", resp.Code, resp.Body.String())
	}

	// Disable KD-SIG-01 with confirmation.
	body := `{"sigId": "KD-SIG-01", "enabled": false, "reason": "Developer debugging session requires this rule disabled", "confirmation": "CHANGE SENTINEL POSTURE"}`
	req, resp = titanRequest(http.MethodPost, "/api/v1/sentinel/signatures/toggle", body, true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}

	// Verify status shows KD-SIG-01 as disabled
	var status struct {
		Signatures []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, sig := range status.Signatures {
		if sig.ID == "KD-SIG-01" {
			found = true
			if sig.Enabled != false {
				t.Fatalf("expected KD-SIG-01 to be false, got %v", sig.Enabled)
			}
		}
	}
	if !found {
		t.Fatal("KD-SIG-01 not found in signatures")
	}

	// Re-enable KD-SIG-01
	body = `{"sigId": "KD-SIG-01", "enabled": true}`
	req, resp = titanRequest(http.MethodPost, "/api/v1/sentinel/signatures/toggle", body, true)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestSentinelToggleSystemApp(t *testing.T) {
	handler, _, _ := newSentinelTestServer(t)

	body := `{"id": "sys_cmd", "enabled": true}`
	req, resp := titanRequest(http.MethodPost, "/api/v1/sentinel/system-apps/toggle", body, true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}

	var status struct {
		SystemApps []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"systemApps"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, app := range status.SystemApps {
		if app.ID == "sys_cmd" {
			found = true
			if app.Enabled != true {
				t.Fatalf("expected sys_cmd to be true, got %v", app.Enabled)
			}
		}
	}
	if !found {
		t.Fatal("sys_cmd not found in systemApps")
	}
}

func TestSentinelV5AliasContract(t *testing.T) {
	handler, _, _ := newSentinelTestServer(t)
	req, resp := titanRequest(http.MethodGet, "/api/v5/sentinel/status", "", true)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("v5 alias status=%d body=%s", resp.Code, resp.Body.String())
	}
	var status struct {
		Signatures []struct {
			Pattern string `json:"pattern"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Signatures) == 0 || status.Signatures[0].Pattern == "" {
		t.Fatal("v5 alias must expose the same signature/pattern contract as v1")
	}
}

func TestSentinelWhitelistLifecycle(t *testing.T) {
	handler, _, _ := newSentinelTestServer(t)

	// 1. Add whitelist entry
	addBody := `{"name": "Dev_Tool", "pathPattern": "C:\\Tools\\mydev.exe"}`
	req, resp := titanRequest(http.MethodPost, "/api/v1/sentinel/whitelist/add", addBody, true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", resp.Code, resp.Body.String())
	}

	var entry mhx.WhitelistEntry
	if err := json.Unmarshal(resp.Body.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.ID == "" || entry.Name != "Dev_Tool" {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	// 2. Toggle whitelist entry
	toggleBody := `{"id": "` + entry.ID + `", "enabled": false}`
	req, resp = titanRequest(http.MethodPost, "/api/v1/sentinel/whitelist/toggle", toggleBody, true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("toggle status=%d body=%s", resp.Code, resp.Body.String())
	}

	// 3. Remove whitelist entry
	removeBody := `{"id": "` + entry.ID + `"}`
	req, resp = titanRequest(http.MethodPost, "/api/v1/sentinel/whitelist/remove", removeBody, true)
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", resp.Code, resp.Body.String())
	}
}
