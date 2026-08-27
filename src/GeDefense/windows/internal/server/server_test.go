// STATUS: DIAMANT VGT SUPREME
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

type fixedEngine struct{ result hardening.Result }
type fixedAudit struct{ result audit.Result }
type fixedXDR struct{ result xdr.Result }
type fixedMHX struct{ mode string }
type fixedIntegrity struct{ status integrity.Status }

func (f fixedEngine) Audit(context.Context) (hardening.Result, error)           { return f.result, nil }
func (f fixedEngine) Enforce(context.Context, string) (hardening.Result, error) { return f.result, nil }
func (f fixedEngine) Components(context.Context) ([]hardening.ComponentStatus, error) {
	return []hardening.ComponentStatus{}, nil
}
func (f fixedEngine) EnforceComponent(context.Context, string) ([]hardening.ComponentStatus, error) {
	return []hardening.ComponentStatus{}, nil
}
func (f fixedEngine) Rollback(context.Context) (hardening.Result, error) { return f.result, nil }
func (f fixedAudit) Run(context.Context) (audit.Result, error)           { return f.result, nil }
func (f fixedXDR) Scan(context.Context) (xdr.Result, error)              { return f.result, nil }
func (f fixedXDR) Last() xdr.Result                                      { return f.result }
func (f *fixedMHX) Status() mhx.Status                                   { return mhx.Status{Engine: "test", ProtectionMode: f.mode} }
func (f *fixedMHX) Analyses(int) []mhx.Analysis                          { return []mhx.Analysis{} }
func (f *fixedMHX) SetMode(mode string) error                            { f.mode = mode; return nil }
func (f *fixedMHX) SyncFeeds(context.Context) error                      { return nil }
func (f *fixedMHX) Applications(context.Context) ([]mhx.ApplicationAllow, error) {
	return []mhx.ApplicationAllow{}, nil
}
func (f *fixedMHX) SetApplication(context.Context, string, string) ([]mhx.ApplicationAllow, error) {
	return []mhx.ApplicationAllow{}, nil
}
func (f *fixedIntegrity) Status() integrity.Status { return f.status }
func (f *fixedIntegrity) Configure(enabled bool, hours int) (integrity.Status, error) {
	f.status.Enabled = enabled
	f.status.IntervalHours = hours
	return f.status, nil
}
func (f *fixedIntegrity) Start() error { f.status.Running = true; return nil }
func (f *fixedIntegrity) Changes(int, int) ([]integrity.Change, error) {
	return []integrity.Change{}, nil
}

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	return New("test", "01234567890123456789012345678901", fixedEngine{result: hardening.Result{Defender: true}}, fixedAudit{result: audit.Result{Checks: []audit.Check{}}}, fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}}, &fixedMHX{mode: "monitor"}, &fixedIntegrity{}, ledger)
}

func TestAPIRequiresBearerToken(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/status", nil)
	request.Host = "127.0.0.1:17831"
	response := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAuthorizedStatusHasSecurityHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/status", nil)
	request.Host = "127.0.0.1:17831"
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("got %d, want %d", response.Code, http.StatusOK)
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("mandatory browser security headers missing")
	}
}

func TestMutationRejectsReplayedRequestID(t *testing.T) {
	handler := newTestServer(t)
	for attempt := 0; attempt < 2; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/evidence/verify", nil)
		request.Host = "127.0.0.1:17831"
		request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
		request.Header.Set("X-VGT-Request-ID", "01234567-89ab-cdef-0123-456789abcdef")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if attempt == 0 && response.Code != http.StatusOK {
			t.Fatalf("first mutation returned %d", response.Code)
		}
		if attempt == 1 && response.Code != http.StatusConflict {
			t.Fatalf("replay returned %d, want %d", response.Code, http.StatusConflict)
		}
	}
}

func TestSovereignModeRequiresExactConfirmation(t *testing.T) {
	handler := newTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/mhx/mode", bytes.NewReader([]byte(`{"mode":"sovereign","confirmation":"wrong"}`)))
	request.Host = "127.0.0.1:17831"
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGT-Request-ID", "22222222-2222-2222-2222-222222222222")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("got %d, want %d", response.Code, http.StatusConflict)
	}
}

func TestApplicationAllowRejectsOversizedPath(t *testing.T) {
	handler := newTestServer(t)
	payload, _ := json.Marshal(map[string]string{"action": "Add", "path": "C:\\" + strings.Repeat("a", 1100) + ".exe"})
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/mhx/applications", bytes.NewReader(payload))
	request.Host = "127.0.0.1:17831"
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGT-Request-ID", "33333333-3333-3333-3333-333333333333")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestBootstrapCodeIsSingleUseAndCreatesHttpOnlySession(t *testing.T) {
	handler := newTestServer(t)
	bootstrapRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/session/bootstrap", bytes.NewReader([]byte("{}")))
	bootstrapRequest.Host = "127.0.0.1:17831"
	bootstrapRequest.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	bootstrapRequest.Header.Set("X-VGT-Request-ID", "11111111-1111-1111-1111-111111111111")
	bootstrapResponse := httptest.NewRecorder()
	handler.ServeHTTP(bootstrapResponse, bootstrapRequest)
	if bootstrapResponse.Code != http.StatusCreated {
		t.Fatalf("bootstrap returned %d", bootstrapResponse.Code)
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(bootstrapResponse.Body.Bytes(), &payload); err != nil || len(payload.Code) != 43 {
		t.Fatal("invalid bootstrap response")
	}
	for attempt := 0; attempt < 2; attempt++ {
		body, _ := json.Marshal(map[string]string{"code": payload.Code})
		exchangeRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/session/exchange", bytes.NewReader(body))
		exchangeRequest.Host = "127.0.0.1:17831"
		exchangeRequest.Header.Set("Content-Type", "application/json")
		exchangeResponse := httptest.NewRecorder()
		handler.ServeHTTP(exchangeResponse, exchangeRequest)
		if attempt == 0 {
			if exchangeResponse.Code != http.StatusOK || len(exchangeResponse.Result().Cookies()) != 1 || !exchangeResponse.Result().Cookies()[0].HttpOnly {
				t.Fatal("bootstrap did not create a protected session cookie")
			}
		} else if exchangeResponse.Code != http.StatusUnauthorized {
			t.Fatalf("reused bootstrap code returned %d", exchangeResponse.Code)
		}
	}
}
