// STATUS: PLATIN
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

func healthyInputs() (hardening.Result, mhx.Status) {
	return hardening.Result{Defender: true, DefenderService: true, RealTimeProtection: true, Firewall: true}, mhx.Status{
		ProtectionHealth: "VERIFIED", ProtectionVerifiedUTC: time.Now(), Realtime: true, TelemetryHeartbeatUTC: time.Now(), NetworkTelemetry: "NATIVE_TCP_OWNER_PID",
		WFPBlockTelemetry:  "POLLING_5157_AUDIT_UNVERIFIED",
		ThreatIntelligence: threatintel.Status{State: "CURRENT", Indicators: 2, BlockingFeedsReady: 1, BlockingFeedsTotal: 1, EnforcementGeneration: "current"},
		ThreatEnforcement:  mhx.ThreatEnforcementStatus{State: "VERIFIED", ActiveGeneration: "current"},
	}
}
func TestHealthRejectsIncompleteAndStaleEvidence(t *testing.T) {
	p, m := healthyInputs()
	if report := evaluateHealth(p, m, true); !report.Healthy {
		t.Fatalf("healthy inputs rejected: %+v", report)
	}
	cases := []struct {
		name     string
		alter    func(*hardening.Result, *mhx.Status)
		evidence bool
	}{
		{"missing defender", func(p *hardening.Result, _ *mhx.Status) { p.Defender = false }, true},
		{"stale heartbeat", func(_ *hardening.Result, m *mhx.Status) { m.TelemetryHeartbeatUTC = time.Now().Add(-time.Minute) }, true},
		{"offline WFP with historical blocks", func(_ *hardening.Result, m *mhx.Status) { m.WFPBlockTelemetry = "DEGRADED"; m.WFPBlockedEvents = 30 }, true},
		{"unverified policy", func(_ *hardening.Result, m *mhx.Status) { m.ProtectionHealth = "STARTING" }, true},
		{"missing verification timestamp", func(_ *hardening.Result, m *mhx.Status) { m.ProtectionVerifiedUTC = time.Time{} }, true},
		{"wrong firewall generation", func(_ *hardening.Result, m *mhx.Status) { m.ThreatEnforcement.ActiveGeneration = "old" }, true},
		{"partial feeds", func(_ *hardening.Result, m *mhx.Status) { m.ThreatIntelligence.BlockingFeedsReady = 0 }, true},
		{"cleanup pending", func(_ *hardening.Result, m *mhx.Status) { m.ThreatEnforcement.State = "VERIFIED_CLEANUP_PENDING" }, true},
		{"broken ledger", func(*hardening.Result, *mhx.Status) {}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, m := healthyInputs()
			tc.alter(&p, &m)
			if evaluateHealth(p, m, tc.evidence).Healthy {
				t.Fatal("unverified control reported healthy")
			}
		})
	}
}

func TestWindowQueueHasOneConsumerAndNoFalseSuccess(t *testing.T) {
	s := &Server{windowCommands: make(chan string, 1), windowClientAt: time.Now()}
	response := httptest.NewRecorder()
	s.queueWindow(response, "maximize")
	if response.Code != http.StatusAccepted {
		t.Fatalf("enqueue: %d", response.Code)
	}
	response = httptest.NewRecorder()
	s.queueWindow(response, "close")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("full queue: %d", response.Code)
	}
	if command := <-s.windowCommands; command != "maximize" {
		t.Fatalf("wrong command: %s", command)
	}
	if len(s.windowCommands) != 0 {
		t.Fatal("command duplicated")
	}
	s.windowClientAt = time.Now().Add(-time.Minute)
	response = httptest.NewRecorder()
	s.queueWindow(response, "close")
	if response.Code != http.StatusServiceUnavailable || len(s.windowCommands) != 0 {
		t.Fatal("disconnected command accepted")
	}
}
func TestWindowAckValidatesAndDisconnects(t *testing.T) {
	s := &Server{windowCommands: make(chan string, 1)}
	for _, body := range []string{`{"state":"bogus"}`, `{"state":"normal","extra":true}`, `{"state":"normal"} {}`} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		response := httptest.NewRecorder()
		req.Header.Set("Content-Type", "application/json")
		s.windowAck(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("accepted invalid acknowledgement: %s", body)
		}
	}
	s.windowCommands <- "maximize"
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"state":"closed"}`))
	request.Header.Set("Content-Type", "application/json")
	s.windowAck(response, request)
	if response.Code != http.StatusOK || !s.windowClientAt.IsZero() || len(s.windowCommands) != 0 {
		t.Fatal("closed host retained active commands")
	}
}
func TestWindowPollCancels(t *testing.T) {
	s := &Server{windowCommands: make(chan string, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	start := time.Now()
	s.windowPoll(httptest.NewRecorder(), request)
	if time.Since(start) > time.Second {
		t.Fatal("poll ignored cancellation")
	}
}
func TestHealthRefreshRequiresAuthentication(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/health/refresh", nil)
	request.RemoteAddr = "127.0.0.1:49152"
	response := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated health refresh: %d", response.Code)
	}
}

func TestHealthStatusUsesMonitorCacheWithoutBlockingAudit(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, m := healthyInputs()
	engine := &measuredHardening{}
	handler := New("test", "01234567890123456789012345678901", engine, fixedAudit{}, fixedXDR{}, &fixedMHX{mode: "guarded", status: m}, &fixedIntegrity{}, ledger)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/health/status", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	req.Header.Set("X-VGT-Request-ID", "22222222-3333-4444-5555-999999999999")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	if engine.audited {
		t.Fatal("startup health status must not block on a fresh PowerShell audit")
	}
}

type measuredHardening struct {
	fixedEngine
	audited bool
}

func (e *measuredHardening) Audit(context.Context) (hardening.Result, error) {
	e.audited = true
	return e.result, nil
}
func (e *measuredHardening) Posture(context.Context) (hardening.Result, error) {
	return hardening.Result{Defender: true, DefenderService: true, RealTimeProtection: true, Firewall: true}, nil
}
func TestHealthRefreshUsesFreshAuditAndVerifiesStoredLedger(t *testing.T) {
	root := t.TempDir()
	ledgerPath := filepath.Join(root, "evidence.jsonl")
	ledger, err := evidence.Open(ledgerPath, filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append("test", "test", "valid"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath, []byte("corrupted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, m := healthyInputs()
	engine := &measuredHardening{}
	handler := New("test", "01234567890123456789012345678901", engine, fixedAudit{}, fixedXDR{}, &fixedMHX{mode: "guarded", status: m}, &fixedIntegrity{}, ledger)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/health/refresh", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	req.Header.Set("X-VGT-Request-ID", "11111111-2222-3333-4444-999999999999")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("refresh status %d: %s", response.Code, response.Body.String())
	}
	var report healthReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !engine.audited || report.Healthy {
		t.Fatal("fresh audit was not authoritative")
	}
	for _, id := range []string{"defender", "firewall", "evidence"} {
		found := false
		for _, check := range report.Checks {
			if check.ID == id {
				found = true
				if check.State != "attention" {
					t.Fatalf("unverified %s was green", id)
				}
			}
		}
		if !found {
			t.Fatalf("missing check %s", id)
		}
	}
}
