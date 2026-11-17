// STATUS: PLATIN VGT SUPREME
package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/spyware"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/witness"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

type fixedV6Provider struct {
	spywareStatus  spyware.Status
	findings       []spyware.Finding
	lockState      string
	bootPosture    winapi.BootPosture
	witnessStatus  witness.StatusReport
	witnessState   string
	witnessReason  string
	lastFoundLimit int
}

func (f *fixedV6Provider) SpywareStatus() spyware.Status { return f.spywareStatus }
func (f *fixedV6Provider) SpywareFindings(limit int) []spyware.Finding {
	f.lastFoundLimit = limit
	if limit < len(f.findings) {
		return append([]spyware.Finding(nil), f.findings[:limit]...)
	}
	return append([]spyware.Finding(nil), f.findings...)
}
func (f *fixedV6Provider) SpywareLockState() string { return f.lockState }
func (f *fixedV6Provider) SetSpywareMode(_ context.Context, mode string) error {
	f.spywareStatus.Mode = mode
	f.spywareStatus.ActiveEnforced = mode == "active"
	return nil
}
func (f *fixedV6Provider) WitnessStatus() witness.StatusReport {
	return f.witnessStatus
}
func (f *fixedV6Provider) WitnessSettingsState() (string, string) {
	return f.witnessState, f.witnessReason
}
func (f *fixedV6Provider) BootPosture() winapi.BootPosture {
	return f.bootPosture
}

func TestV6StatusEndpointReturnsHonestProjection(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	v6 := &fixedV6Provider{
		spywareStatus: spyware.Status{
			Enabled:          true,
			BYOVDWatched:     true,
			CapabilityWatch:  true,
			PersistenceWatch: true,
			LSASSWatch:       true,
			Findings:         1,
			LastScanUTC:      time.Now().UTC(),
		},
		findings: []spyware.Finding{{
			ID:       "byovd-0001",
			Source:   spyware.SourceBYOVD,
			Severity: spyware.SeverityCritical,
			Title:    "Known vulnerable driver",
			Response: "OBSERVE_ONLY",
		}},
		lockState: "UNAVAILABLE",
		witnessStatus: witness.StatusReport{
			Status:  witness.StatusFault,
			Enabled: true,
		},
		witnessState:  "MISSING",
		witnessReason: "witness/settings.json is not provisioned",
	}

	_, handler := newServerWithV6(
		"5.3.0",
		testMasterToken,
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		&fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{},
		ledger, nil, nil, nil, v6,
	)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/v6/status?limit=999", nil)
	req.Host = "127.0.0.1:17831"
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set("Authorization", "Bearer "+testMasterToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if v6.lastFoundLimit != v6MaxLimit {
		t.Fatalf("expected bounded limit %d, got %d", v6MaxLimit, v6.lastFoundLimit)
	}
	var payload v6StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode v6 status: %v", err)
	}
	if !payload.Spyware.Enabled || len(payload.SpywareFindings) != 1 {
		t.Fatalf("unexpected spyware projection: %+v", payload.Spyware)
	}
	if payload.Witness.Status != witness.StatusFault || payload.Witness.SettingsState != "MISSING" {
		t.Fatalf("unexpected witness projection: %+v", payload.Witness)
	}
	if payload.Styx.Mode != mhx.StyxModeOff || payload.Styx.SensorState != "unavailable" {
		t.Fatalf("unexpected styx fallback: %+v", payload.Styx)
	}
}

func TestV6StatusRequiresAuthAndHandlesNilProvider(t *testing.T) {
	handler := newTestServer(t)

	unauthReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/v6/status", nil)
	unauthReq.Host = "127.0.0.1:17831"
	unauthReq.RemoteAddr = "127.0.0.1:49152"
	unauth := httptest.NewRecorder()
	handler.ServeHTTP(unauth, unauthReq)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", unauth.Code)
	}

	okReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/v6/status", nil)
	okReq.Host = "127.0.0.1:17831"
	okReq.RemoteAddr = "127.0.0.1:49152"
	okReq.Header.Set("Authorization", "Bearer "+testMasterToken)
	ok := httptest.NewRecorder()
	handler.ServeHTTP(ok, okReq)
	if ok.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", ok.Code, ok.Body.String())
	}
}

func TestV6ModeSwitchTightensWithoutFrictionAndRequiresConfirmationToWeaken(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	v6 := &fixedV6Provider{
		spywareStatus: spyware.Status{Enabled: true, Mode: "observe"},
		lockState:     "UNAVAILABLE",
	}
	_, handler := newServerWithV6(
		"6.0.0", testMasterToken,
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		&fixedMHX{mode: "guarded", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{}, ledger, nil, nil, nil, v6,
	)

	activateReq, activateRec := titanRequest(http.MethodPost, "/api/v1/v6/mode", `{"spywareMode":"active","styxMode":"enforce"}`, true)
	handler.ServeHTTP(activateRec, activateReq)
	if activateRec.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", activateRec.Code, activateRec.Body.String())
	}
	if !v6.spywareStatus.ActiveEnforced || v6.spywareStatus.Mode != "active" {
		t.Fatalf("expected active spyware mode, got %+v", v6.spywareStatus)
	}

	weakenUnconfirmed, weakenRec := titanRequest(http.MethodPost, "/api/v1/v6/mode", `{"spywareMode":"observe"}`, true)
	handler.ServeHTTP(weakenRec, weakenUnconfirmed)
	if weakenRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for unconfirmed weaken, got %d body=%s", weakenRec.Code, weakenRec.Body.String())
	}
}

type fakeStyxMHX struct {
	*fixedMHX
	whitelist []string
	blocked   []string
	incidents []mhx.StyxIncident
	programs  []mhx.StyxProgramTrafficSummary
}

func (f *fakeStyxMHX) StyxIncidents(int) []mhx.StyxIncident { return f.incidents }
func (f *fakeStyxMHX) StyxWhitelist() []string              { return append([]string(nil), f.whitelist...) }
func (f *fakeStyxMHX) SetStyxWhitelist(_ context.Context, entries []string) ([]string, error) {
	norm, err := mhx.NormalizeStyxWhitelist(entries)
	if err != nil {
		return nil, err
	}
	f.whitelist = norm
	f.blocked = nil
	return append([]string(nil), norm...), nil
}
func (f *fakeStyxMHX) StyxBlockedTargets() []string { return append([]string(nil), f.blocked...) }
func (f *fakeStyxMHX) StyxProgramTraffic() []mhx.StyxProgramTrafficSummary {
	return f.programs
}

func TestV6StyxWhitelistEndpointEnrichesGeoAndClearsBlockedTargets(t *testing.T) {
	root := t.TempDir()
	csvPath := filepath.Join(root, "geoip.csv")
	contents := "network,country_code,country_name,latitude,longitude,asn,as_name\n8.8.8.0/24,US,United States,37,-97,AS15169,Google LLC\n"
	if err := os.WriteFile(csvPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(contents))
	if err := os.WriteFile(csvPath+".sha256", []byte(fmt.Sprintf("%x  geoip.csv\n", digest)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GEDEFENSE_GEOIP_CSV", csvPath)

	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	mhxMock := &fakeStyxMHX{
		fixedMHX: &fixedMHX{mode: "guarded", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		blocked:  []string{"8.8.8.8/32"},
		incidents: []mhx.StyxIncident{{
			ID:          "INC-STYX-1",
			PID:         4242,
			Process:     "app.exe",
			ProcessPath: `C:\Apps\app.exe`,
			Remote:      "8.8.8.8:443",
			Score:       250,
			Action:      "wfp-blocked",
		}},
	}
	v6 := &fixedV6Provider{spywareStatus: spyware.Status{Enabled: true, Mode: "observe"}, lockState: "UNAVAILABLE"}
	_, handler := newServerWithV6(
		"6.0.0", testMasterToken,
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		mhxMock, &fixedIntegrity{}, ledger, nil, nil, nil, v6,
	)

	getReq, getRec := titanRequest(http.MethodGet, "/api/v1/v6/status", "", true)
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var payload struct {
		StyxIncidents      []v6StyxIncidentView `json:"styxIncidents"`
		StyxBlockedTargets []string             `json:"styxBlockedTargets"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.StyxIncidents) != 1 || payload.StyxIncidents[0].CountryCode != "US" || payload.StyxIncidents[0].ASN != "AS15169" || payload.StyxIncidents[0].ProcessPath != `C:\Apps\app.exe` {
		t.Fatalf("expected geoip+path enrichment on incident, got %+v", payload.StyxIncidents)
	}

	shortReq, shortRec := titanRequest(http.MethodPost, "/api/v1/v6/styx/whitelist", `{"action":"add","entry":"8.8.8.8","reason":"short"}`, true)
	handler.ServeHTTP(shortRec, shortReq)
	if shortRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on short reason, got %d", shortRec.Code)
	}

	addReq, addRec := titanRequest(http.MethodPost, "/api/v1/v6/styx/whitelist", `{"action":"add","entry":"C:\\Apps\\app.exe","reason":"Verified IDE connection needed by operator"}`, true)
	handler.ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("whitelist add status=%d body=%s", addRec.Code, addRec.Body.String())
	}
	if len(mhxMock.whitelist) != 1 || len(mhxMock.blocked) != 0 {
		t.Fatalf("expected whitelist stored and blocked cleared, wl=%v blocked=%v", mhxMock.whitelist, mhxMock.blocked)
	}
}
