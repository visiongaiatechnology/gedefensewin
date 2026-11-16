// STATUS: PLATIN
package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

const (
	// testCenterImage/testTrayImage live inside the administrator-owned install
	// tree. The test fixtures model the verdict the Windows resolver computes
	// (trusted tree + Authenticode); the real derivation is exercised by
	// operatorPeerFromPID on Windows.
	testCenterImage  = `C:\Program Files\VGT\GeDefense\bin\GeDefenseCenter.exe`
	testTrayImage    = `C:\Program Files\VGT\GeDefense\bin\GeDefenseTray.exe`
	testForeignImage = `C:\Users\Public\evil.exe`
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

// brokerPeerResolver builds the deterministic peer seam. It models exactly the
// kernel/token verdict the production resolver returns: process image path, tree
// trust, Authenticode state and token elevation.
func brokerPeerResolver(imagePath string, operatorAuthorised, elevated, trusted, signed bool) func(*Server) {
	return func(s *Server) {
		s.peerPID = func(string) (uint32, error) { return 4242, nil }
		s.operatorPeer = func(pid uint32) (operatorPeer, error) {
			if pid != 4242 {
				return operatorPeer{}, errors.New("unexpected peer pid")
			}
			return operatorPeer{
				PID:                    pid,
				Account:                `VGT-TEST\operator`,
				SID:                    "S-1-5-21-1111-2222-3333-1001",
				Operator:               operatorAuthorised,
				Elevated:               elevated,
				ImagePath:              imagePath,
				ImageTrusted:           trusted,
				ImageSignatureVerified: signed,
			}, nil
		}
	}
}

// centreBrokerFixture models an elevated, signed Center binary in the install
// tree (the full-authority launcher).
func centreBrokerFixture(operatorAuthorised bool) func(*Server) {
	return brokerPeerResolver(testCenterImage, operatorAuthorised, true, true, true)
}

// trayBrokerFixture models a signed Tray binary in the install tree. The Tray
// never runs elevated and must never receive more than read authority.
func trayBrokerFixture(operatorAuthorised bool) func(*Server) {
	return brokerPeerResolver(testTrayImage, operatorAuthorised, false, true, true)
}

func TestOperatorBrokerMintsFullScopeCenterSession(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	centreBrokerFixture(true)(server)
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
	trayBrokerFixture(true)(server)
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
	authorised := centreBrokerFixture(true)
	denied := centreBrokerFixture(false)
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

// TestOperatorBrokerRejectsUntrustedCallerImage is the FIND-WIN-006 regression:
// an arbitrary user process (foreign path, unsigned/unverified image or a client
// role that does not match the actual signed binary) must never receive a token.
func TestOperatorBrokerRejectsUntrustedCallerImage(t *testing.T) {
	cases := []struct {
		name   string
		client string
		config func(*Server)
	}{
		{"foreign process image", operatorBrokerCenter, brokerPeerResolver(testForeignImage, true, true, false, false)},
		{"trusted tree but dev-unsigned", operatorBrokerCenter, brokerPeerResolver(testCenterImage, true, true, true, false)},
		{"not tree-trusted", operatorBrokerCenter, brokerPeerResolver(`C:\Users\Public\GeDefenseCenter.exe`, true, true, false, true)},
		{"center role claimed by tray binary", operatorBrokerCenter, trayBrokerFixture(true)},
		{"tray role claimed by center binary", operatorBrokerTray, centreBrokerFixture(true)},
		{"missing image path", operatorBrokerCenter, brokerPeerResolver("", true, true, false, false)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server, handler := newSecurityTestServer(t)
			testCase.config(server)
			record := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
				`{"client":"`+testCase.client+`"}`, withBrokerHeader(), withReplayID())
			if record.Code != http.StatusForbidden {
				t.Fatalf("untrusted caller status = %d, want 403: %s", record.Code, record.Body.String())
			}
			if payload := decodeBody(t, record); payload["token"] != nil {
				t.Fatalf("untrusted caller received a session token: %v", payload)
			}
		})
	}
}

// TestOperatorBrokerScopeBinding proves the client header cannot upgrade scope:
// the client role is bound exactly to the verified binary (a Center process
// cannot even claim the smaller Tray role), and a scope field in the body is
// rejected outright.
func TestOperatorBrokerScopeBinding(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	centreBrokerFixture(true)(server)
	crossRole := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"tray"}`, withBrokerHeader(), withReplayID())
	if crossRole.Code != http.StatusForbidden {
		t.Fatalf("center binary claiming the tray role status = %d, want 403: %s", crossRole.Code, crossRole.Body.String())
	}
	if payload := decodeBody(t, crossRole); payload["token"] != nil {
		t.Fatalf("cross-role broker request received a token: %v", payload)
	}
	escalation := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"center-launcher","scopes":["read","operate","policy","window"]}`,
		withBrokerHeader(), withReplayID())
	if escalation.Code != http.StatusBadRequest {
		t.Fatalf("broker accepted a client-supplied scope list: %d %s", escalation.Code, escalation.Body.String())
	}
}

// TestOperatorBrokerNonElevatedCenterLosesPolicyScope pins the elevation gate:
// a medium-IL Center session is bounded to read+operate and cannot reach policy
// mutations or window registration.
func TestOperatorBrokerNonElevatedCenterLosesPolicyScope(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	brokerPeerResolver(testCenterImage, true, false, true, true)(server)
	record := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"center-launcher"}`, withBrokerHeader(), withReplayID())
	if record.Code != http.StatusCreated {
		t.Fatalf("non-elevated center status = %d: %s", record.Code, record.Body.String())
	}
	payload := decodeBody(t, record)
	token, _ := payload["token"].(string)
	scopes, _ := payload["scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "operate" {
		t.Fatalf("non-elevated center must be bounded to read+operate: %v", scopes)
	}
	if denied := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback",
		`{"confirmation":"ROLLBACK HARDENING","reason":"non-elevated broker session escalation attempt"}`,
		withBearer(token), withReplayID()); denied.Code != http.StatusForbidden {
		t.Fatalf("non-elevated center session reached a policy mutation: %d %s", denied.Code, denied.Body.String())
	}
}

func TestOperatorBrokerRejectedAttemptsDoNotLockOutOperator(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	brokerPeerResolver(testCenterImage, false, true, true, true)(server)
	for attempt := 0; attempt < 5; attempt++ {
		record := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
			`{"client":"center-launcher"}`, withBrokerHeader(), withReplayID())
		if record.Code != http.StatusForbidden {
			t.Fatalf("unauthorised attempt %d status = %d, want 403", attempt, record.Code)
		}
	}
	// The legitimate operator must not be rate limited by the rejected attempts.
	centreBrokerFixture(true)(server)
	allowed := callHandler(handler, http.MethodPost, "/api/v1/session/operator",
		`{"client":"center-launcher"}`, withBrokerHeader(), withReplayID())
	if allowed.Code != http.StatusCreated {
		t.Fatalf("legitimate operator was locked out after rejected attempts: %d %s", allowed.Code, allowed.Body.String())
	}
}

func TestOperatorPeerImageAuthorisationPredicate(t *testing.T) {
	signed := operatorPeer{ImagePath: testCenterImage, ImageTrusted: true, ImageSignatureVerified: true}
	tests := []struct {
		name   string
		peer   operatorPeer
		client string
		want   bool
	}{
		{"trusted signed center", signed, operatorBrokerCenter, true},
		{"trusted signed center as tray", signed, operatorBrokerTray, false},
		{"missing image", operatorPeer{ImageTrusted: true, ImageSignatureVerified: true}, operatorBrokerCenter, false},
		{"untrusted tree", operatorPeer{ImagePath: testForeignImage, ImageTrusted: false, ImageSignatureVerified: true}, operatorBrokerCenter, false},
		{"unsigned image", operatorPeer{ImagePath: testCenterImage, ImageTrusted: true, ImageSignatureVerified: false}, operatorBrokerCenter, false},
		{"parent-directory escape", operatorPeer{ImagePath: `C:\Program Files\VGT\GeDefenseEvil\GeDefenseCenter.exe`, ImageTrusted: false, ImageSignatureVerified: true}, operatorBrokerCenter, false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := testCase.peer.imageAuthorisedFor(testCase.client); got != testCase.want {
				t.Fatalf("imageAuthorisedFor(%s) = %t, want %t", testCase.client, got, testCase.want)
			}
		})
	}
	if scopes := operatorScopesFor(operatorBrokerTray, operatorPeer{Elevated: true}); scopes != scopeRead {
		t.Fatalf("tray scopes = %v, want read only", scopes.names())
	}
	if scopes := operatorScopesFor(operatorBrokerCenter, operatorPeer{}); scopes != scopeRead|scopeOperate {
		t.Fatalf("non-elevated center scopes = %v, want read+operate", scopes.names())
	}
	if scopes := operatorScopesFor(operatorBrokerCenter, operatorPeer{Elevated: true}); scopes != scopeAll {
		t.Fatalf("elevated center scopes = %v, want all", scopes.names())
	}
}

func TestOperatorBrokerReplayIsRejected(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	centreBrokerFixture(true)(server)
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
	trayBrokerFixture(true)(server)
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
	// The authorized bucket must be a real budget, not an unauthorised-request
	// rejection: every earlier attempt was created successfully.
	if lastStatus == http.StatusForbidden {
		t.Fatal("authorized broker requests were rejected as unauthorized")
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

// TestOperatorBrokerRequestRoleBinding keeps the exact client identifiers the
// shipped operatorclient uses; a rename would silently break Center/Tray.
func TestOperatorBrokerRequestRoleBinding(t *testing.T) {
	if operatorBrokerCenter != "center-launcher" || operatorBrokerTray != "tray" {
		t.Fatalf("broker client identifiers changed: center=%q tray=%q", operatorBrokerCenter, operatorBrokerTray)
	}
	if !strings.HasSuffix(operatorCenterExecutable, ".exe") || !strings.HasSuffix(operatorTrayExecutable, ".exe") {
		t.Fatalf("executable bindings are not Windows images: %q %q", operatorCenterExecutable, operatorTrayExecutable)
	}
}
