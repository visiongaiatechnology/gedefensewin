// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
)

type symbiosisTestMHX struct {
	*fixedMHX
	status       mhx.DefenderSymbiosisStatus
	containments []mhx.ContainmentRecord
	scanErr      error
	scanResult   mhx.DefenderScanResult
}

func (s *symbiosisTestMHX) SymbiosisStatus() mhx.DefenderSymbiosisStatus {
	return s.status
}

func (s *symbiosisTestMHX) Containments() []mhx.ContainmentRecord {
	return append([]mhx.ContainmentRecord(nil), s.containments...)
}

func (s *symbiosisTestMHX) ResumeContainment(id, reason string) (mhx.ContainmentRecord, error) {
	for i := range s.containments {
		if s.containments[i].ID == id {
			s.containments[i].State = mhx.ContainmentResumed
			s.containments[i].Outcome = "resumed: " + reason
			return s.containments[i], nil
		}
	}
	return mhx.ContainmentRecord{}, errors.New("containment not found")
}

func (s *symbiosisTestMHX) TerminateContainment(id, reason string) (mhx.ContainmentRecord, error) {
	for i := range s.containments {
		if s.containments[i].ID == id {
			s.containments[i].State = mhx.ContainmentTerminated
			s.containments[i].Outcome = "terminated: " + reason
			return s.containments[i], nil
		}
	}
	return mhx.ContainmentRecord{}, errors.New("containment not found")
}

func (s *symbiosisTestMHX) ScanFileWithDefender(_ context.Context, path string) (mhx.DefenderScanResult, error) {
	if s.scanErr != nil {
		return mhx.DefenderScanResult{}, s.scanErr
	}
	res := s.scanResult
	res.TargetPath = path
	return res, nil
}

func (s *symbiosisTestMHX) ReconcileDefenderSymbiosis(context.Context, bool, string) error {
	s.status.AutoHealsTriggered++
	return nil
}

func TestSymbiosisAndContainmentSecurityGates(t *testing.T) {
	baseServer, _ := newSecurityTestServer(t)
	mock := &symbiosisTestMHX{
		fixedMHX: &fixedMHX{mode: "guarded", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		status: mhx.DefenderSymbiosisStatus{
			Enabled:            true,
			SubscribedEventIDs: []int{1116, 1121, 1123, 5001},
			ActiveContainments: 1,
		},
		containments: []mhx.ContainmentRecord{
			{
				ID:        "cnt-abcdef01",
				State:     mhx.ContainmentFrozen,
				Source:    "defender.1123",
				RootPID:   4455,
				RootImage: "suspicious.exe",
			},
		},
		scanErr: errors.New(`internal C:\ProgramData\VGT\secret\detail: access denied`),
	}
	_, handler := newServer("test", testMasterToken, baseServer.engine, baseServer.audit, baseServer.xdr, mock, baseServer.integrity, baseServer.ledger, nil, nil, nil)

	readToken := mintSession(t, handler, "reader", "read")
	operateToken := mintSession(t, handler, "operator", "read", "operate")
	policyToken := mintSession(t, handler, "policy-admin", "read", "operate", "policy")

	// Read-only session can inspect symbiosis/containments, never trigger actions.
	if resp := callHandler(handler, http.MethodGet, "/api/v1/mhx/symbiosis", "", withBearer(readToken)); resp.Code != http.StatusOK {
		t.Fatalf("read session blocked from /mhx/symbiosis: %d", resp.Code)
	}
	if resp := callHandler(handler, http.MethodPost, "/api/v1/mhx/defender/scan-file", `{"path":"C:\\Tools\\app.exe"}`, withBearer(readToken), withReplayID()); resp.Code != http.StatusForbidden {
		t.Fatalf("read session executed defender scan: %d", resp.Code)
	}
	if resp := callHandler(handler, http.MethodPost, "/api/v1/mhx/containments/cnt-abcdef01/resume",
		`{"confirmation":"RESUME CONTAINED PROCESS","reason":"operator approved release"}`, withBearer(operateToken), withReplayID()); resp.Code != http.StatusForbidden {
		t.Fatalf("operate-only session released frozen containment: %d", resp.Code)
	}

	// Scan error must never leak raw internal paths to clients (AN-FIND-009).
	scanResp := callHandler(handler, http.MethodPost, "/api/v1/mhx/defender/scan-file", `{"path":"C:\\Tools\\app.exe"}`, withBearer(operateToken), withReplayID())
	if scanResp.Code != http.StatusConflict {
		t.Fatalf("expected 409 on scan failure, got %d", scanResp.Code)
	}
	if strings.Contains(scanResp.Body.String(), "ProgramData") || strings.Contains(scanResp.Body.String(), "secret") {
		t.Fatalf("internal scan error detail leaked to client: %s", scanResp.Body.String())
	}

	// Containment resume requires replay ID, typed confirmation, and 8+ char reason.
	noConfirm := callHandler(handler, http.MethodPost, "/api/v1/mhx/containments/cnt-abcdef01/resume",
		`{"reason":"missing typed phrase"}`, withBearer(policyToken), withReplayID())
	if noConfirm.Code != http.StatusConflict {
		t.Fatalf("resume without typed confirmation status=%d, want 409", noConfirm.Code)
	}
	shortReason := callHandler(handler, http.MethodPost, "/api/v1/mhx/containments/cnt-abcdef01/resume",
		`{"confirmation":"RESUME CONTAINED PROCESS","reason":"short"}`, withBearer(policyToken), withReplayID())
	if shortReason.Code != http.StatusBadRequest {
		t.Fatalf("resume with short reason status=%d, want 400", shortReason.Code)
	}
	accepted := callHandler(handler, http.MethodPost, "/api/v1/mhx/containments/cnt-abcdef01/resume",
		`{"confirmation":"RESUME CONTAINED PROCESS","reason":"verified false positive signed binary"}`, withBearer(policyToken), withReplayID())
	if accepted.Code != http.StatusOK {
		t.Fatalf("valid resume failed: %d %s", accepted.Code, accepted.Body.String())
	}
	payload := decodeBody(t, accepted)
	if payload["state"] != string(mhx.ContainmentResumed) {
		t.Fatalf("unexpected state after resume: %+v", payload)
	}
	_ = time.Second
}
