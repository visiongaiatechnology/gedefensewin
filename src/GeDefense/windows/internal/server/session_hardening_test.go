// STATUS: PLATIN VGT SUPREME
package server

import (
	"net/http"
	"testing"
)

// replayEntryCount reports the current number of occupied replay slots.
func replayEntryCount(server *Server) int {
	server.replay.mu.Lock()
	defer server.replay.mu.Unlock()
	return len(server.replay.items)
}

// TestExchangeDummyBearerFloodKeepsReplayTableAndMutationPath is the
// FIND-WIN-007 regression: a flood with a bogus Authorization header must be
// budgeted by the exchange endpoint itself, must not occupy replay slots and
// must never turn legitimate mutations into HTTP 409 conflicts.
func TestExchangeDummyBearerFloodKeepsReplayTableAndMutationPath(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	for attempt := 0; attempt < maxExchangeAttemptsPerMinute; attempt++ {
		record := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
			withOrigin("http://127.0.0.1:17831"), withBearer("x"), withReplayID())
		if record.Code != http.StatusUnauthorized {
			t.Fatalf("exchange flood attempt %d status = %d, want 401: %s", attempt, record.Code, record.Body.String())
		}
	}
	limited := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
		withOrigin("http://127.0.0.1:17831"), withBearer("x"), withReplayID())
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("exchange flood was not rate limited: %d %s", limited.Code, limited.Body.String())
	}
	if limited.Header().Get("Retry-After") == "" {
		t.Fatal("exchange rate-limit response is missing Retry-After")
	}
	if occupied := replayEntryCount(server); occupied != 0 {
		t.Fatalf("unauthenticated exchange attempts occupied %d replay slots", occupied)
	}
	// A legitimate confirmed mutation must still pass: the bounded replay table
	// was never touched by the flood.
	allowed := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback",
		`{"confirmation":"ROLLBACK HARDENING","reason":"legitimate operator mutation after exchange flood"}`,
		withMaster(), withReplayID())
	if allowed.Code != http.StatusOK {
		t.Fatalf("legitimate mutation was denied after exchange flood: %d %s", allowed.Code, allowed.Body.String())
	}
}

// TestExchangeReplayGuardAppliesAfterPeerBinding proves the replay guard still
// protects real exchange requests, while a replay rejection does not consume the
// one pending browser registration.
func TestExchangeReplayGuardAppliesAfterPeerBinding(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.peerPID = func(string) (uint32, error) { return 4242, nil }
	register := func() {
		t.Helper()
		record := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
			`{"pid":4242}`, withMaster(), withReplayID())
		if record.Code != http.StatusCreated {
			t.Fatalf("register status = %d: %s", record.Code, record.Body.String())
		}
	}
	requestID := "0a1b2c3d-4e5f-4a6b-8c7d-0000000000aa"
	exchange := func(id string) int {
		record := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
			withOrigin("http://127.0.0.1:17831"), withReplayValue(id))
		return record.Code
	}
	register()
	if status := exchange(requestID); status != http.StatusOK {
		t.Fatalf("first exchange status = %d, want 200", status)
	}
	register()
	if status := exchange(requestID); status != http.StatusConflict {
		t.Fatalf("replayed exchange status = %d, want 409", status)
	}
	// The registration must survive the replay rejection: a fresh request id is
	// accepted exactly once afterwards.
	if status := exchange(nextRequestID()); status != http.StatusOK {
		t.Fatalf("fresh exchange after replay rejection status = %d, want 200", status)
	}
	if status := exchange(nextRequestID()); status != http.StatusUnauthorized {
		t.Fatalf("consumed registration accepted a second exchange: %d", status)
	}
}

// TestBrowserRegistrationSearchUsesWholePendingSlice is the FIND-WIN-020
// regression: the exchange must match the peer against every pending
// registration, not only the newest slice entry.
func TestBrowserRegistrationSearchUsesWholePendingSlice(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.peerPID = func(string) (uint32, error) { return 4242, nil }
	for _, pid := range []string{"4242", "5555"} {
		record := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
			`{"pid":`+pid+`}`, withMaster(), withReplayID())
		if record.Code != http.StatusCreated {
			t.Fatalf("register pid %s status = %d: %s", pid, record.Code, record.Body.String())
		}
	}
	accepted := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
		withOrigin("http://127.0.0.1:17831"), withReplayID())
	if accepted.Code != http.StatusOK || len(accepted.Result().Cookies()) != 1 {
		t.Fatalf("exchange did not find the matching earlier registration: %d %s", accepted.Code, accepted.Body.String())
	}
}

// TestBrowserRegistrationIsUniquePerProcess pins the duplicate cleanup: a
// repeated registration for the same launcher child replaces the old one instead
// of creating an ambiguous duplicate expectation.
func TestBrowserRegistrationIsUniquePerProcess(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.peerPID = func(string) (uint32, error) { return 4242, nil }
	for attempt := 0; attempt < 2; attempt++ {
		record := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
			`{"pid":4242}`, withMaster(), withReplayID())
		if record.Code != http.StatusCreated {
			t.Fatalf("register %d status = %d: %s", attempt, record.Code, record.Body.String())
		}
	}
	server.sessionMu.Lock()
	registrations := len(server.browserRegistrations)
	server.sessionMu.Unlock()
	if registrations != 1 {
		t.Fatalf("duplicate browser registrations retained: %d", registrations)
	}
	if status := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
		withOrigin("http://127.0.0.1:17831"), withReplayID()).Code; status != http.StatusOK {
		t.Fatalf("exchange after duplicate registration status = %d", status)
	}
	if status := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
		withOrigin("http://127.0.0.1:17831"), withReplayID()).Code; status != http.StatusUnauthorized {
		t.Fatalf("registration was not single-use: %d", status)
	}
}

// TestSessionRateBucketsArePerSessionNotPerClient is the FIND-WIN-018 rate
// regression: two sessions that share the same client name must not share one
// budget, and window control stays reachable for the verified operator session
// even though a non-elevated Center is bounded to read+operate.
func TestSessionRateBucketsArePerSessionNotPerClient(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	first := mintSession(t, handler, "shared-console", "read")
	second := mintSession(t, handler, "shared-console", "read")
	for index := 0; index < 600; index++ {
		if status := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(first)).Code; status != http.StatusOK {
			t.Fatalf("first session read %d status = %d", index, status)
		}
	}
	if status := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(first)).Code; status != http.StatusTooManyRequests {
		t.Fatalf("first session budget not enforced: %d", status)
	}
	// Same client name, different session: its own bucket must still be open.
	if status := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(second)).Code; status != http.StatusOK {
		t.Fatalf("second session with the same client name was starved: %d", status)
	}
	_ = server
}

// TestOperatorSessionMayControlWindowKeepsTrayOut documents the bounded window
// authority: a verified Center operator session with operate may drive the
// window host, while a read-only Tray broker session may not.
func TestOperatorSessionMayControlWindowKeepsTrayOut(t *testing.T) {
	centerAuth := authContext{session: &sessionRecord{operator: true}, scopes: scopeRead | scopeOperate}
	if !operatorSessionMayControlWindow(centerAuth) {
		t.Fatal("verified center operator session must be able to control the window")
	}
	trayAuth := authContext{session: &sessionRecord{operator: true}, scopes: scopeRead}
	if operatorSessionMayControlWindow(trayAuth) {
		t.Fatal("read-only tray session must not control the window")
	}
	nonOperator := authContext{session: &sessionRecord{}, scopes: scopeRead | scopeOperate}
	if operatorSessionMayControlWindow(nonOperator) {
		t.Fatal("non-operator session must not control the window")
	}
}
