// STATUS: PLATIN VGT SUPREME
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
