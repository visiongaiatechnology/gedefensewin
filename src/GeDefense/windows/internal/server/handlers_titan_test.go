// STATUS: DIAMANT VGT SUPREME
package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/titan"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

func newTitanTestServer(t *testing.T) (http.Handler, *titan.Engine) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	titanEngine, err := titan.New(filepath.Join(root, "titan"), "5.1.0", ledger)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWithTitan("5.1.0", "01234567890123456789012345678901",
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		&fixedMHX{mode: "guarded", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{}, ledger, nil, nil, titanEngine)
	t.Cleanup(func() { _ = titanEngine.Close() })
	return handler, titanEngine
}

func titanRequest(method, path, body string, authorized bool) (*http.Request, *httptest.ResponseRecorder) {
	request := httptest.NewRequest(method, "http://127.0.0.1:17831"+path, bytes.NewBufferString(body))
	request.Host = "127.0.0.1:17831"
	request.RemoteAddr = "127.0.0.1:49152"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGT-Request-ID", titanRequestID())
	if authorized {
		request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	}
	response := httptest.NewRecorder()
	return request, response
}

func titanRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	}
	encoded := hex.EncodeToString(raw)
	return encoded[0:8] + "-" + encoded[8:12] + "-4" + encoded[13:16] + "-8" + encoded[17:20] + "-" + encoded[20:32]
}

func TestTitanStatusRequiresAuthAndReportsHonestState(t *testing.T) {
	handler, _ := newTitanTestServer(t)
	request, response := titanRequest(http.MethodGet, "/api/v1/titan/status", "", false)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", response.Code)
	}
	request, response = titanRequest(http.MethodGet, "/api/v1/titan/status", "", true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var status titan.Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Version != "5.1.0" || status.Mode != titan.ModeObserve {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.Witness.Configured || status.Witness.Detail == "" {
		t.Fatalf("witness must be explicit and unconfigured: %+v", status.Witness)
	}
	if len(status.Sensors) < 5 {
		t.Fatalf("sensor projection incomplete: %+v", status.Sensors)
	}
}

func TestTitanPolicyMutationAndAuditEvent(t *testing.T) {
	handler, engine := newTitanTestServer(t)
	request, response := titanRequest(http.MethodPost, "/api/v1/titan/policy",
		`{"mode":"CONTAIN","autoQuarantine":true,"reason":"Operator aktiviert Titan Containment fuer neue Ingest-Objekte"}`, true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("policy status=%d body=%s", response.Code, response.Body.String())
	}
	var policy titan.Policy
	if err := json.Unmarshal(response.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Mode != titan.ModeContain || !policy.AutoQuarantine {
		t.Fatalf("policy not applied: %+v", policy)
	}
	request, response = titanRequest(http.MethodGet, "/api/v1/titan/events?limit=10&filter=all", "", true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("events status=%d body=%s", response.Code, response.Body.String())
	}
	var events struct {
		Events []titan.Event `json:"events"`
		Total  int           `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if events.Total < 1 || events.Events[0].Type != titan.EventSelfIntegrity {
		t.Fatalf("policy audit event missing: %+v", events)
	}
	verification := engine.Verify()
	if !verification.Verified {
		t.Fatalf("titan evidence did not verify: %+v", verification)
	}
}

func TestTitanPermitLifecycleAndDevelopmentRoot(t *testing.T) {
	handler, engine := newTitanTestServer(t)
	request, response := titanRequest(http.MethodPost, "/api/v1/titan/permits",
		`{"path":"C:\\Users\\Operator\\Downloads\\approved.exe","sha256":"","action":"FILE_CREATED","ttlMinutes":60,"singleUse":true,"reason":"Besitzer genehmigt genau diesen Installer","confirmation":"CREATE TITAN PERMIT"}`, true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("permit status=%d body=%s", response.Code, response.Body.String())
	}
	if permits := engine.Permits(); len(permits) != 1 || !permits[0].SingleUse {
		t.Fatalf("permit not persisted: %+v", permits)
	}
	request, response = titanRequest(http.MethodPost, "/api/v1/titan/permits/permit-missing/revoke",
		`{"reason":"Freigabe widerrufen und entfernt"}`, true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("missing permit revoke status=%d", response.Code)
	}
	request, response = titanRequest(http.MethodPost, "/api/v1/titan/development-roots",
		`{"path":"C:\\Users\\Operator\\Projects\\MyApp","reason":"Owner markiert den lokalen Projektbaum als Entwicklungsbaum","confirmation":"ADD DEVELOPMENT ROOT"}`, true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("development root status=%d body=%s", response.Code, response.Body.String())
	}
	if roots := engine.Policy().DevelopmentRoots; len(roots) != 1 {
		t.Fatalf("development root not persisted: %+v", roots)
	}
}

func TestTitanRejectsUnknownPolicyFields(t *testing.T) {
	handler, _ := newTitanTestServer(t)
	request, response := titanRequest(http.MethodPost, "/api/v1/titan/policy",
		`{"mode":"CONTAIN","autoQuarantine":true,"reason":"Operator aktiviert Containment","evil":"x"}`, true)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", response.Code, response.Body.String())
	}
}
