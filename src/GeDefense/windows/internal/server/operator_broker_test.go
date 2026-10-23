// STATUS: PLATIN
package server

import (
	"errors"
	"net/http"
	"testing"
)

func withBrokerHeader() requestOption {
	return func(r *http.Request) {
		r.Header.Set("X-VGT-Operator-Broker", operatorBrokerValue)
	}
}

func withReplayValue(id string) requestOption {
	return func(r *http.Request) {
		r.Header.Set("X-VGT-Request-ID", id)
	}
}

func brokerPeerFixtures(operatorAuthorised bool) func(*Server) {
	return func(s *Server) {
		s.peerPID = func(string) (uint32, error) { return 4242, nil }
		s.operatorPeer = func(pid uint32) (operatorPeer, error) {
			if pid != 4242 {
				return operatorPeer{}, errors.New("unexpected peer pid")
			}
			return operatorPeer{
				PID:      pid,
				Account:  `VGT-TEST\operator`,
				SID:      "S-1-5-21-1111-2222-3333-1001",
				Operator: operatorAuthorised,
			}, nil
		}
	}
}

func TestOperatorBrokerMintsFullScopeCenterSession(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	brokerPeerFixtures(true)(server)
	record := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"center-launcher"}`, withBrokerHeader(), withReplayID())
	if record.Code != http.StatusCreated {
		t.Fatalf("broker status = %d, want 201: %s", record.Code, record.Body.String())
	}
	payload := decodeBody(t, record)
	token, _ := payload["token"].(string)
	if len(token) < len("vgs.")+10 || token[:4] != "vgs." {
		t.Fatalf("broker returned no scoped session token: %q", token)
	}
	scopes, _ := payload["scopes"].([]any)
	if len(scopes) != 4 {
		t.Fatalf("center broker session must carry all four scopes: %v", scopes)
	}
	subject, _ := payload["subject"].(map[string]any)
	if subject["account"] != `VGT-TEST\operator` {
		t.Fatalf("subject account missing: %v", subject)
	}

	state := callHandler(handler, http.MethodGet, "/api/v1/session/state", "", withBearer(token))
	if state.Code != http.StatusOK {
		t.Fatalf("state with broker session = %d: %s", state.Code, state.Body.String())
	}
	statePayload := decodeBody(t, state)
	if statePayload["operator"] != true || statePayload["client"] != operatorBrokerCenter {
		t.Fatalf("state does not expose the OS-bound operator identity: %v", statePayload)
	}

	// The OS-verified center session may register the browser child process.
	registration := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
		`{"pid":31337,"client":"center"}`, withBearer(token), withReplayID())
	if registration.Code != http.StatusCreated {
		t.Fatalf("operator session cannot register browser: %d %s", registration.Code, registration.Body.String())
	}
}

func TestOperatorBrokerTraySessionIsReadOnly(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	brokerPeerFixtures(true)(server)
	record := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"tray"}`, withBrokerHeader(), withReplayID())
	if record.Code != http.StatusCreated {
		t.Fatalf("tray broker status = %d: %s", record.Code, record.Body.String())
	}
	payload := decodeBody(t, record)
	token, _ := payload["token"].(string)
	scopes, _ := payload["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Fatalf("tray session must be read-only: %v", scopes)
	}
	// Read works.
	if status := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(token)); status.Code != http.StatusOK {
		t.Fatalf("tray read session rejected: %d", status.Code)
	}
	// Policy and window registration stay closed for the tray session.
	if denied := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
		`{"pid":1,"client":"center"}`, withBearer(token), withReplayID()); denied.Code != http.StatusForbidden {
		t.Fatalf("tray session registered a browser: %d", denied.Code)
	}
	if denied := callHandler(handler, http.MethodPost, "/api/v1/mhx/mode",
		`{"mode":"guarded"}`, withBearer(token), withReplayID()); denied.Code != http.StatusForbidden {
		t.Fatalf("tray session reached a policy mutation: %d", denied.Code)
	}
}

func TestOperatorBrokerFailsClosed(t *testing.T) {
	newServerWith := func(t *testing.T, configure func(*Server)) http.Handler {
		t.Helper()
		server, handler := newSecurityTestServer(t)
		configure(server)
		return handler
	}
	authorised := brokerPeerFixtures(true)
	denied := brokerPeerFixtures(false)
	validBody := `{"client":"center-launcher"}`

	tests := []struct {
		name   string
		body   string
		opts   []requestOption
		config func(*Server)
		want   int
	}{
		{"missing broker marker", validBody, []requestOption{withReplayID()}, authorised, http.StatusForbidden},
		{"browser origin", validBody, []requestOption{withBrokerHeader(), withReplayID(), withOrigin("http://127.0.0.1:17831")}, authorised, http.StatusForbidden},
		{"authorization header", validBody, []requestOption{withBrokerHeader(), withReplayID(), withMaster()}, authorised, http.StatusForbidden},
		{"cookie credential", validBody, []requestOption{withBrokerHeader(), withReplayID(), withCookie(&http.Cookie{Name: "VGTSESSION", Value: "vgs.abcdef"})}, authorised, http.StatusForbidden},
		{"unknown client", `{"client":"something-else"}`, []requestOption{withBrokerHeader(), withReplayID()}, authorised, http.StatusBadRequest},
		{"malformed body", `{"client":`, []requestOption{withBrokerHeader(), withReplayID()}, authorised, http.StatusBadRequest},
		{"missing replay id", validBody, []requestOption{withBrokerHeader()}, authorised, http.StatusConflict},
		{"peer lookup error", validBody, []requestOption{withBrokerHeader(), withReplayID()}, func(s *Server) {
			s.peerPID = func(string) (uint32, error) { return 0, errors.New("lookup failed") }
		}, http.StatusForbidden},
		{"identity error", validBody, []requestOption{withBrokerHeader(), withReplayID()}, func(s *Server) {
			s.peerPID = func(string) (uint32, error) { return 4242, nil }
			s.operatorPeer = func(uint32) (operatorPeer, error) { return operatorPeer{}, errors.New("token unavailable") }
		}, http.StatusForbidden},
		{"non-operator identity", validBody, []requestOption{withBrokerHeader(), withReplayID()}, denied, http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newServerWith(t, test.config)
			record := callHandler(handler, http.MethodPost, "/api/v1/session/operator", test.body, test.opts...)
			if record.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", record.Code, test.want, record.Body.String())
			}
		})
	}
}

func TestOperatorBrokerReplayIsRejected(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	brokerPeerFixtures(true)(server)
	requestID := "0a1b2c3d-4e5f-4a6b-8c7d-000000000123"
	first := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"center-launcher"}`, withBrokerHeader(), withReplayValue(requestID))
	if first.Code != http.StatusCreated {
		t.Fatalf("first broker request = %d: %s", first.Code, first.Body.String())
	}
	second := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"center-launcher"}`, withBrokerHeader(), withReplayValue(requestID))
	if second.Code != http.StatusConflict {
		t.Fatalf("replayed broker request = %d, want 409", second.Code)
	}
}

func TestOperatorBrokerRateLimitApplies(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	brokerPeerFixtures(true)(server)
	lastStatus := 0
	for attempt := 0; attempt < 12; attempt++ {
		record := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
			`{"client":"tray"}`, withBrokerHeader(), withReplayID())
		lastStatus = record.Code
		if record.Code == http.StatusTooManyRequests {
			break
		}
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("broker rate limit did not engage, last status %d", lastStatus)
	}
}

func TestOperatorPeerAuthorisationPredicate(t *testing.T) {
	if (operatorPeer{}).authorised() {
		t.Fatal("empty peer must not be authorised")
	}
	if !(operatorPeer{Operator: true}).authorised() {
		t.Fatal("operator group member must be authorised")
	}
	if !(operatorPeer{Administrator: true}).authorised() {
		t.Fatal("administrator must be authorised")
	}
	if (operatorPeer{Account: "x"}).authorised() {
		t.Fatal("plain account must not be authorised")
	}
}
