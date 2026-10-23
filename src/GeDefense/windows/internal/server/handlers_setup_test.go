package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/startup"
)

func TestSetupStatusAndCompletionRequireVerifiedPosture(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := startup.Open(filepath.Join(root, "startup-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine := fixedEngine{result: hardening.Result{
		Defender: true, DefenderService: true, RealTimeProtection: true,
		ASRRules: 11, ASRBlockRules: 11, ControlledFolderAccess: true,
	}}
	handler := NewWithStartup("5.2.0", "01234567890123456789012345678901", engine, fixedAudit{}, fixedXDR{},
		&fixedMHX{status: mhx.Status{ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{status: integrity.Status{Enabled: true, State: "SCHEDULED"}}, ledger, gate, nil)

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/setup/status", nil)
	request.Host = "127.0.0.1:17831"
	request.RemoteAddr = "127.0.0.1:49152"
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("X-VGT-Request-ID", "11111111-2222-4333-8444-555555555555")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("setup status = %d: %s", response.Code, response.Body.String())
	}
	var status struct {
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil || status.Complete {
		t.Fatalf("fresh setup must be incomplete: body=%s err=%v", response.Body.String(), err)
	}

	body, _ := json.Marshal(map[string]string{
		"profile": "business", "reason": "First-run setup after verified protection posture.",
		"confirmation": setupConfirmation,
	})
	completeRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/setup/complete", bytes.NewReader(body))
	completeRequest.Host = "127.0.0.1:17831"
	completeRequest.RemoteAddr = "127.0.0.1:49152"
	completeRequest.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	completeRequest.Header.Set("Content-Type", "application/json")
	completeRequest.Header.Set("X-VGT-Request-ID", "22222222-3333-4444-8555-666666666666")
	completeResponse := httptest.NewRecorder()
	handler.ServeHTTP(completeResponse, completeRequest)
	if completeResponse.Code != http.StatusOK {
		t.Fatalf("setup complete = %d: %s", completeResponse.Code, completeResponse.Body.String())
	}
	again, err := gate.SetupStatus("5.2.0")
	if err != nil || !again.Complete || again.Profile != "business" {
		t.Fatalf("setup marker not persisted: %+v err=%v", again, err)
	}
}
