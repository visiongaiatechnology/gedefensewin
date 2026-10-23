// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

type feedPolicyMHX struct {
	fixedMHX
	policy         mhx.FeedPolicySnapshot
	setErr         error
	captured       []mhx.FeedActionUpdate
	capturedReason string
}

func (f *feedPolicyMHX) FeedPolicy() mhx.FeedPolicySnapshot { return f.policy }

func (f *feedPolicyMHX) SetFeedActions(_ context.Context, updates []mhx.FeedActionUpdate, reason string) (mhx.FeedPolicySnapshot, error) {
	f.captured = append([]mhx.FeedActionUpdate(nil), updates...)
	f.capturedReason = reason
	if f.setErr != nil {
		return f.policy, f.setErr
	}
	return f.policy, nil
}

func feedPolicyTestServer(t *testing.T, engine MHXEngine) *Server {
	t.Helper()
	return &Server{mhx: engine}
}

func feedPolicyTestRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mhx/threat-intelligence/feed-policy", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestFeedPolicyGetRejectsUnavailableProvider(t *testing.T) {
	server := feedPolicyTestServer(t, &fixedMHX{})
	response := httptest.NewRecorder()
	server.mhxFeedPolicy(response, httptest.NewRequest(http.MethodGet, "/x", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable provider status = %d, want 503", response.Code)
	}
}

func TestFeedPolicyGetReturnsProviderSnapshot(t *testing.T) {
	server := feedPolicyTestServer(t, &feedPolicyMHX{policy: mhx.FeedPolicySnapshot{SchemaVersion: threatintel.FeedPolicySchemaVersion, StoreState: "DEFAULT", EnforcementState: "UNVERIFIED", Pending: true}})
	response := httptest.NewRecorder()
	server.mhxFeedPolicy(response, httptest.NewRequest(http.MethodGet, "/x", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var snapshot mhx.FeedPolicySnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("response decode: %v", err)
	}
	if snapshot.StoreState != "DEFAULT" || !snapshot.Pending || snapshot.SchemaVersion != threatintel.FeedPolicySchemaVersion {
		t.Fatalf("snapshot not forwarded honestly: %+v", snapshot)
	}
}

func TestFeedPolicySetValidatesConfirmationReasonAndEntries(t *testing.T) {
	server := feedPolicyTestServer(t, &feedPolicyMHX{})
	cases := map[string]string{
		"missing-confirmation": `{"feeds":[{"feedId":"cins_army","action":"BLOCK"}],"reason":"Operator promotes CINS Army"}`,
		"short-reason":         `{"feeds":[{"feedId":"cins_army","action":"BLOCK"}],"reason":"short","confirmation":"UPDATE THREAT FEED POLICY"}`,
		"no-feeds":             `{"feeds":[],"reason":"Operator promotes CINS Army","confirmation":"UPDATE THREAT FEED POLICY"}`,
		"oversized-feed-id":    `{"feeds":[{"feedId":"` + strings.Repeat("a", 40) + `","action":"BLOCK"}],"reason":"Operator promotes CINS Army","confirmation":"UPDATE THREAT FEED POLICY"}`,
		"oversized-action":     `{"feeds":[{"feedId":"cins_army","action":"` + strings.Repeat("B", 30) + `"}],"reason":"Operator promotes CINS Army","confirmation":"UPDATE THREAT FEED POLICY"}`,
		"unknown-field":        `{"feeds":[{"feedId":"cins_army","action":"BLOCK","extra":true}],"reason":"Operator promotes CINS Army","confirmation":"UPDATE THREAT FEED POLICY"}`,
		"trailing-json":        `{"feeds":[{"feedId":"cins_army","action":"BLOCK"}],"reason":"Operator promotes CINS Army","confirmation":"UPDATE THREAT FEED POLICY"} {}`,
	}
	for name, body := range cases {
		response := httptest.NewRecorder()
		server.mhxSetFeedPolicy(response, feedPolicyTestRequest(body))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400 (%s)", name, response.Code, response.Body.String())
		}
	}
}

func TestFeedPolicySetForwardsValidatedMutation(t *testing.T) {
	engine := &feedPolicyMHX{policy: mhx.FeedPolicySnapshot{SchemaVersion: threatintel.FeedPolicySchemaVersion, StoreState: "DEFAULT"}}
	server := feedPolicyTestServer(t, engine)
	response := httptest.NewRecorder()
	server.mhxSetFeedPolicy(response, feedPolicyTestRequest(`{"feeds":[{"feedId":"cins_army","action":"BLOCK"},{"feedId":"tor_exit","action":"ANNOTATE_ONLY"}],"reason":"Operator promotes CINS Army for a blocking pilot","confirmation":"UPDATE THREAT FEED POLICY"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("valid mutation status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if len(engine.captured) != 2 || engine.captured[0].FeedID != "cins_army" || engine.captured[1].Action != "ANNOTATE_ONLY" {
		t.Fatalf("handler did not forward validated updates: %+v", engine.captured)
	}
	if engine.capturedReason != "Operator promotes CINS Army for a blocking pilot" {
		t.Fatalf("handler changed the reason: %q", engine.capturedReason)
	}
}

func TestFeedPolicySetSurfacesEngineRejectionExplicitly(t *testing.T) {
	engine := &feedPolicyMHX{setErr: errors.New("feed policy requires validated indicators for all 5 blocking feeds (4 ready); synchronize feeds first")}
	server := feedPolicyTestServer(t, engine)
	response := httptest.NewRecorder()
	server.mhxSetFeedPolicy(response, feedPolicyTestRequest(`{"feeds":[{"feedId":"cins_army","action":"BLOCK"}],"reason":"Operator promotes CINS Army for a blocking pilot","confirmation":"UPDATE THREAT FEED POLICY"}`))
	if response.Code != http.StatusConflict {
		t.Fatalf("rejected mutation status = %d, want 409", response.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error response decode: %v", err)
	}
	message := payload["error"]
	if !strings.Contains(message, "feed policy rejected") || !strings.Contains(message, "validated indicators") {
		t.Fatalf("rejection detail is not explicit: %q", message)
	}
	if payload["errorId"] == "" {
		t.Fatal("error id missing from rejection response")
	}
}

func TestFeedPolicySetRejectsUnavailableProvider(t *testing.T) {
	server := feedPolicyTestServer(t, &fixedMHX{})
	response := httptest.NewRecorder()
	server.mhxSetFeedPolicy(response, feedPolicyTestRequest(`{"feeds":[{"feedId":"cins_army","action":"BLOCK"}],"reason":"Operator promotes CINS Army for a blocking pilot","confirmation":"UPDATE THREAT FEED POLICY"}`))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable provider status = %d, want 503", response.Code)
	}
}
