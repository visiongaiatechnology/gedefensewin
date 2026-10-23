// STATUS: PLATIN
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/security"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

const testMasterToken = "01234567890123456789012345678901"

func newSecurityTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	return newServer("test", testMasterToken,
		fixedEngine{result: hardening.Result{Defender: true}},
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		&fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{}, ledger, nil, nil, nil)
}

var requestSequence int

func nextRequestID() string {
	requestSequence++
	return fmt.Sprintf("0a1b2c3d-4e5f-4a6b-8c7d-%012x", requestSequence)
}

type requestOption func(*http.Request)

func withMaster() requestOption {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testMasterToken) }
}

func withBearer(token string) requestOption {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func withCookie(cookie *http.Cookie) requestOption {
	return func(r *http.Request) { r.AddCookie(cookie) }
}

func withOrigin(origin string) requestOption {
	return func(r *http.Request) { r.Header.Set("Origin", origin) }
}

func withReplayID() requestOption {
	return func(r *http.Request) { r.Header.Set("X-VGT-Request-ID", nextRequestID()) }
}

func callHandler(handler http.Handler, method, path, body string, options ...requestOption) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, "http://127.0.0.1:17831"+path, reader)
	request.Host = "127.0.0.1:17831"
	request.RemoteAddr = "127.0.0.1:49152"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, option := range options {
		option(request)
	}
	record := httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	return record
}

func decodeBody(t *testing.T, record *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(record.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, record.Body.String())
	}
	return payload
}

// exchangeBootstrapSession creates a cookie session through the legacy
// master-authorized bootstrap code path.
func exchangeBootstrapSession(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	bootstrap := callHandler(handler, http.MethodPost, "/api/v1/session/bootstrap", "{}", withMaster(), withReplayID())
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	payload := decodeBody(t, bootstrap)
	code, _ := payload["code"].(string)
	if code == "" {
		t.Fatal("bootstrap code missing")
	}
	exchange := callHandler(handler, http.MethodPost, "/api/v1/session/exchange",
		`{"code":"`+code+`"}`, withOrigin("http://127.0.0.1:17831"), withReplayID())
	if exchange.Code != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", exchange.Code, exchange.Body.String())
	}
	cookies := exchange.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("exchange did not create a hardened session cookie: %+v", cookies)
	}
	return cookies[0]
}

func mintSession(t *testing.T, handler http.Handler, client string, scopes ...string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client": client, "scopes": scopes, "lifetimeSeconds": 3600})
	response := callHandler(handler, http.MethodPost, "/api/v1/admin/sessions", string(body), withMaster(), withReplayID())
	if response.Code != http.StatusCreated {
		t.Fatalf("admin session status=%d body=%s", response.Code, response.Body.String())
	}
	payload := decodeBody(t, response)
	token, _ := payload["token"].(string)
	if !strings.HasPrefix(token, sessionIDPrefix) {
		t.Fatalf("admin session token malformed: %q", token)
	}
	return token
}

func TestSecurityHeadersArePresentOnEarlyRejections(t *testing.T) {
	_, handler := newSecurityTestServer(t)

	badHost := httptest.NewRequest(http.MethodGet, "http://evil.example:17831/api/v1/status", nil)
	badHost.Host = "evil.example:17831"
	badHost.RemoteAddr = "127.0.0.1:49152"
	badHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(badHostResponse, badHost)
	if badHostResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad host status=%d", badHostResponse.Code)
	}
	assertSecurityHeaders(t, badHostResponse)

	badPeer := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831/api/v1/status", nil)
	badPeer.Host = "127.0.0.1:17831"
	badPeer.RemoteAddr = "10.0.0.5:49152"
	badPeerResponse := httptest.NewRecorder()
	handler.ServeHTTP(badPeerResponse, badPeer)
	if badPeerResponse.Code != http.StatusForbidden {
		t.Fatalf("bad peer status=%d", badPeerResponse.Code)
	}
	assertSecurityHeaders(t, badPeerResponse)

	for index := 0; index < maxUnauthenticatedRequestsPerMinute+1; index++ {
		response := callHandler(handler, http.MethodGet, "/api/v1/status", "")
		if index < maxUnauthenticatedRequestsPerMinute {
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated request %d status=%d", index, response.Code)
			}
			continue
		}
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("rate limit status=%d, want 429", response.Code)
		}
		if response.Header().Get("Retry-After") == "" {
			t.Fatal("rate-limit response is missing Retry-After")
		}
		assertSecurityHeaders(t, response)
	}

	// A flood without credentials must not starve the local break-glass client.
	master := callHandler(handler, http.MethodGet, "/api/v1/status", "", withMaster())
	if master.Code != http.StatusOK {
		t.Fatalf("master was starved by anonymous flood: %d %s", master.Code, master.Body.String())
	}
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("early response is missing Cache-Control: no-store")
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("early response is missing Content-Security-Policy")
	}
	if response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("early response is missing X-Content-Type-Options")
	}
	if response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("early response is missing X-Frame-Options")
	}
}

func TestReplayIDIsMandatoryOnEveryMutationPath(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	cases := []struct {
		name string
		path string
		body string
	}{
		{"master bootstrap", "/api/v1/session/bootstrap", "{}"},
		{"master window ack", "/api/v1/window/ack", `{"state":"normal"}`},
		{"public exchange", "/api/v1/session/exchange", "{}"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			options := []requestOption{withMaster()}
			if testCase.name == "public exchange" {
				options = []requestOption{withOrigin("http://127.0.0.1:17831")}
			}
			response := callHandler(handler, http.MethodPost, testCase.path, testCase.body, options...)
			if response.Code != http.StatusConflict {
				t.Fatalf("missing replay id status=%d body=%s", response.Code, response.Body.String())
			}
			options = append(options, withReplayID())
			allowed := callHandler(handler, http.MethodPost, testCase.path, testCase.body, options...)
			if allowed.Code == http.StatusConflict {
				t.Fatalf("unique replay id rejected: %d %s", allowed.Code, allowed.Body.String())
			}
		})
	}
}

func TestScopedSessionsEnforceFunctionalAuthorization(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	readOnly := mintSession(t, handler, "tray-read", "read")
	operateOnly := mintSession(t, handler, "operator-service", "read", "operate")
	policy := mintSession(t, handler, "admin-service", "read", "operate", "policy")

	status := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(readOnly))
	if status.Code != http.StatusOK {
		t.Fatalf("read session status=%d body=%s", status.Code, status.Body.String())
	}
	downgradeBody := `{"confirmation":"ROLLBACK HARDENING","reason":"operator requested rollback"}`
	rejected := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback", downgradeBody, withBearer(readOnly), withReplayID())
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("read-only session mutated security posture: %d %s", rejected.Code, rejected.Body.String())
	}
	operateRejected := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback", downgradeBody, withBearer(operateOnly), withReplayID())
	if operateRejected.Code != http.StatusForbidden {
		t.Fatalf("operate-only session changed policy: %d %s", operateRejected.Code, operateRejected.Body.String())
	}
	policyAllowed := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback", downgradeBody, withBearer(policy), withReplayID())
	if policyAllowed.Code != http.StatusOK {
		t.Fatalf("policy session rejected: %d %s", policyAllowed.Code, policyAllowed.Body.String())
	}

	state := callHandler(handler, http.MethodGet, "/api/v1/session/state", "", withBearer(operateOnly))
	if state.Code != http.StatusOK {
		t.Fatalf("session state status=%d body=%s", state.Code, state.Body.String())
	}
	payload := decodeBody(t, state)
	if payload["client"] != "operator-service" {
		t.Fatalf("session state lost client attribution: %v", payload)
	}
}

func TestWindowScopedSessionCannotReadControlPlane(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	windowSession := mintSession(t, handler, "center-launcher", "window")
	state := callHandler(handler, http.MethodGet, "/api/v1/window/state", "", withBearer(windowSession))
	if state.Code != http.StatusOK {
		t.Fatalf("window state status=%d body=%s", state.Code, state.Body.String())
	}
	ack := callHandler(handler, http.MethodPost, "/api/v1/window/ack", `{"state":"normal"}`, withBearer(windowSession), withReplayID())
	if ack.Code != http.StatusOK {
		t.Fatalf("window ack status=%d body=%s", ack.Code, ack.Body.String())
	}
	read := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(windowSession))
	if read.Code != http.StatusForbidden {
		t.Fatalf("window-only session read the control plane: %d %s", read.Code, read.Body.String())
	}
	mutation := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback",
		`{"confirmation":"ROLLBACK HARDENING","reason":"window session escalation attempt"}`, withBearer(windowSession), withReplayID())
	if mutation.Code != http.StatusForbidden {
		t.Fatalf("window-only session mutated policy: %d %s", mutation.Code, mutation.Body.String())
	}
}

func TestDowngradeMutationsRequireTypedConfirmationAndReason(t *testing.T) {
	cases := []struct {
		path         string
		confirmation string
		payload      string
	}{
		{"/api/v1/hardening/enforce", confirmationHardeningProfile, `{"profile":"EnterpriseBalanced"}`},
		{"/api/v1/hardening/rollback", confirmationHardeningRollback, `{}`},
		{"/api/v1/hardening/components", confirmationHardeningComponent, `{"id":"defender-realtime"}`},
		{"/api/v1/integrity/configuration", confirmationIntegrityMonitoring, `{"enabled":false,"intervalHours":24}`},
		{"/api/v1/mhx/applications", confirmationApplicationAllowlist, `{"action":"Add","path":"C:\\Tools\\operator.exe"}`},
		{"/api/v1/titan/development-roots", confirmationAddDevelopmentRoot, `{"path":"C:\\Projects\\app"}`},
		{"/api/v1/titan/development-roots/remove", confirmationRemoveDevelopmentRoot, `{"path":"C:\\Projects\\app"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.path, func(t *testing.T) {
			// Fresh server per case: the long-running operation budget is
			// intentionally tight (AN-FIND-006), so cases must not share it.
			_, caseHandler := newSecurityTestServer(t)
			body := addJSONField(testCase.payload, "reason", "operator intent for regression test")
			rejected := callHandler(caseHandler, http.MethodPost, testCase.path, body, withMaster(), withReplayID())
			if rejected.Code != http.StatusConflict {
				t.Fatalf("missing confirmation status=%d body=%s", rejected.Code, rejected.Body.String())
			}
			shortReason := addJSONField(addJSONField(testCase.payload, "confirmation", testCase.confirmation), "reason", "short")
			shortResponse := callHandler(caseHandler, http.MethodPost, testCase.path, shortReason, withMaster(), withReplayID())
			if shortResponse.Code != http.StatusBadRequest {
				t.Fatalf("short reason status=%d body=%s", shortResponse.Code, shortResponse.Body.String())
			}
			valid := addJSONField(addJSONField(testCase.payload, "confirmation", testCase.confirmation), "reason", "operator intent for regression test")
			allowed := callHandler(caseHandler, http.MethodPost, testCase.path, valid, withMaster(), withReplayID())
			if allowed.Code == http.StatusConflict || allowed.Code == http.StatusBadRequest {
				t.Fatalf("valid confirmation rejected: %d %s", allowed.Code, allowed.Body.String())
			}
		})
	}
}

// addJSONField inserts a field into a flat JSON object payload.
func addJSONField(payload, key, value string) string {
	encodedKey, _ := json.Marshal(key)
	encodedValue, _ := json.Marshal(value)
	trimmed := strings.TrimSpace(payload)
	if trimmed == "{}" || trimmed == "" {
		return "{" + string(encodedKey) + ":" + string(encodedValue) + "}"
	}
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return payload
	}
	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	field := string(encodedKey) + ":" + string(encodedValue)
	if inner == "" {
		return "{" + field + "}"
	}
	return "{" + inner + "," + field + "}"
}

func TestLogoutRevokesOnlyTheCallingSession(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	first := exchangeBootstrapSession(t, handler)
	second := exchangeBootstrapSession(t, handler)

	before := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(first))
	if before.Code != http.StatusOK {
		t.Fatalf("cookie session status=%d body=%s", before.Code, before.Body.String())
	}
	logout := callHandler(handler, http.MethodPost, "/api/v1/session/logout", "{}",
		withCookie(first), withOrigin("http://127.0.0.1:17831"), withReplayID())
	if logout.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", logout.Code, logout.Body.String())
	}
	after := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(first))
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session still authorized: %d %s", after.Code, after.Body.String())
	}
	other := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(second))
	if other.Code != http.StatusOK {
		t.Fatalf("logout revoked an unrelated session: %d", other.Code)
	}
}

func TestRevokeAllSessionsInvalidatesBrowserAndServiceSessions(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	cookie := exchangeBootstrapSession(t, handler)
	service := mintSession(t, handler, "tray-read", "read")
	revoke := callHandler(handler, http.MethodPost, "/api/v1/admin/sessions/revoke-all", "{}", withMaster(), withReplayID())
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke-all status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(cookie)); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked cookie session status=%d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(service)); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked service session status=%d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withMaster()); response.Code != http.StatusOK {
		t.Fatalf("master credential was revoked by revoke-all: %d", response.Code)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	clock := time.Now()
	server.now = func() time.Time { return clock }
	token := mintSession(t, handler, "tray-read", "read")
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(token)); response.Code != http.StatusOK {
		t.Fatalf("fresh session status=%d", response.Code)
	}
	clock = clock.Add(sessionIdleLifetime + time.Minute)
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(token)); response.Code != http.StatusUnauthorized {
		t.Fatalf("idle session status=%d, want 401", response.Code)
	}

	// Sessions minted with an explicit one-hour lifetime must end at that
	// absolute deadline even while the operator keeps the idle timer warm.
	absolute := mintSession(t, handler, "tray-absolute", "read") // lifetimeSeconds=3600
	for index := 0; index < 5; index++ {
		clock = clock.Add(10 * time.Minute)
		if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(absolute)); response.Code != http.StatusOK {
			t.Fatalf("active session status=%d at +%d0m", response.Code, index+1)
		}
	}
	clock = clock.Add(11 * time.Minute)
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(absolute)); response.Code != http.StatusUnauthorized {
		t.Fatalf("absolute-expired session status=%d, want 401", response.Code)
	}
}

func TestCookieSessionRotatesWithGrace(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	clock := time.Now()
	server.now = func() time.Time { return clock }
	cookie := exchangeBootstrapSession(t, handler)

	clock = clock.Add(sessionRotationInterval + time.Minute)
	rotated := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(cookie))
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotation request status=%d body=%s", rotated.Code, rotated.Body.String())
	}
	replacementCookies := rotated.Result().Cookies()
	if len(replacementCookies) != 1 || replacementCookies[0].Value == cookie.Value {
		t.Fatalf("session was not rotated: %+v", replacementCookies)
	}
	replacement := replacementCookies[0]

	// The old token keeps working inside the short grace window (concurrent
	// browser requests must not fail mid-rotation).
	clock = clock.Add(5 * time.Second)
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(cookie)); response.Code != http.StatusOK {
		t.Fatalf("old session token rejected inside grace: %d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(replacement)); response.Code != http.StatusOK {
		t.Fatalf("rotated session token rejected: %d", response.Code)
	}
	clock = clock.Add(sessionRotationGrace + time.Second)
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(cookie)); response.Code != http.StatusUnauthorized {
		t.Fatalf("retired session token still accepted after grace: %d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(replacement)); response.Code != http.StatusOK {
		t.Fatalf("rotated session token was not authoritative: %d", response.Code)
	}
}

func TestBrowserRegistrationBindsExchangeToProcess(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.peerPID = func(string) (uint32, error) { return 4242, nil }

	register := func(pid int) *httptest.ResponseRecorder {
		return callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
			fmt.Sprintf(`{"pid":%d}`, pid), withMaster(), withReplayID())
	}
	if response := register(1234); response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	exchangeWith := func() *httptest.ResponseRecorder {
		return callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
			withOrigin("http://127.0.0.1:17831"), withReplayID())
	}
	if response := exchangeWith(); response.Code != http.StatusUnauthorized {
		t.Fatalf("exchange from foreign process accepted: %d %s", response.Code, response.Body.String())
	}

	if response := register(4242); response.Code != http.StatusCreated {
		t.Fatalf("second register status=%d", response.Code)
	}
	// The most recent registration (4242) matches the resolved peer process.
	accepted := exchangeWith()
	if accepted.Code != http.StatusOK || len(accepted.Result().Cookies()) != 1 {
		t.Fatalf("peer-bound exchange rejected: %d %s", accepted.Code, accepted.Body.String())
	}
	if replay := exchangeWith(); replay.Code != http.StatusUnauthorized {
		t.Fatalf("browser registration was not single-use: %d", replay.Code)
	}
}

func TestPeerBindingFailsClosedWithoutRegistration(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.peerPID = func(string) (uint32, error) { return uint32(os.Getpid()), nil }
	exchange := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
		withOrigin("http://127.0.0.1:17831"), withReplayID())
	if exchange.Code != http.StatusUnauthorized {
		t.Fatalf("exchange without registration status=%d", exchange.Code)
	}
	// A registration with a different PID must not be satisfiable by claiming a
	// matching process id: the server resolves the peer independently.
	register := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser",
		fmt.Sprintf(`{"pid":%d}`, os.Getpid()+1), withMaster(), withReplayID())
	if register.Code != http.StatusCreated {
		t.Fatalf("register status=%d", register.Code)
	}
	exchange = callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}",
		withOrigin("http://127.0.0.1:17831"), withReplayID())
	if exchange.Code != http.StatusUnauthorized {
		t.Fatalf("exchange for a different pid accepted: %d", exchange.Code)
	}
}

func TestMasterTokenReloadInvalidatesCopiedCredential(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	tokenPath := filepath.Join(programData, "VGT", "GeDefense", "dashboard.token")
	if _, err := security.LoadOrCreateToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, handler := newServer("test", testMasterToken,
		fixedEngine{}, fixedAudit{}, fixedXDR{},
		&fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{}, ledger, nil, nil, nil)
	cookie := exchangeBootstrapSession(t, handler)

	replacement, err := security.RotateToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if security.TokenEqual(replacement, testMasterToken) {
		t.Fatal("rotation did not change the stored credential")
	}
	reload := callHandler(handler, http.MethodPost, "/api/v1/admin/token/reload", "{}", withBearer(testMasterToken), withReplayID())
	if reload.Code != http.StatusOK {
		t.Fatalf("reload status=%d body=%s", reload.Code, reload.Body.String())
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(testMasterToken)); response.Code != http.StatusUnauthorized {
		t.Fatalf("stale master credential still accepted: %d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(replacement)); response.Code != http.StatusOK {
		t.Fatalf("reloaded master credential rejected: %d %s", response.Code, response.Body.String())
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(cookie)); response.Code != http.StatusUnauthorized {
		t.Fatalf("session survived credential reload: %d", response.Code)
	}
}

func TestMasterTokenRotationRevokesSessionsAndNeverReturnsSecret(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	tokenPath := filepath.Join(programData, "VGT", "GeDefense", "dashboard.token")
	initial, err := security.LoadOrCreateToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, handler := newServer("test", testMasterToken,
		fixedEngine{}, fixedAudit{}, fixedXDR{},
		&fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{}, ledger, nil, nil, nil)
	cookie := exchangeBootstrapSession(t, handler)

	rotate := callHandler(handler, http.MethodPost, "/api/v1/admin/token/rotate", "{}", withBearer(testMasterToken), withReplayID())
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotate.Code, rotate.Body.String())
	}
	rotatedToken, err := security.ReadToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if security.TokenEqual(rotatedToken, testMasterToken) || security.TokenEqual(rotatedToken, initial) {
		t.Fatal("rotate did not replace the credential file")
	}
	if strings.Contains(rotate.Body.String(), rotatedToken) || strings.Contains(rotate.Body.String(), testMasterToken) || strings.Contains(rotate.Body.String(), initial) {
		t.Fatal("rotation response leaked a credential")
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(testMasterToken)); response.Code != http.StatusUnauthorized {
		t.Fatalf("old master credential still accepted after rotation: %d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(rotatedToken)); response.Code != http.StatusOK {
		t.Fatalf("new master credential rejected: %d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withCookie(cookie)); response.Code != http.StatusUnauthorized {
		t.Fatalf("session survived credential rotation: %d", response.Code)
	}
}

func TestSessionRateBudgetIsPerSessionAndClass(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.now = func() time.Time { return time.Now() }
	sessionToken := mintSession(t, handler, "tray-read", "read")
	for index := 0; index < 600; index++ {
		response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(sessionToken))
		if response.Code != http.StatusOK {
			t.Fatalf("read budget exhausted early at %d: %d", index, response.Code)
		}
	}
	limited := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(sessionToken))
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("session read budget not enforced: %d", limited.Code)
	}
	// Another identity keeps its own budget and the master is not starved.
	other := mintSession(t, handler, "second-reader", "read")
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withBearer(other)); response.Code != http.StatusOK {
		t.Fatalf("second session was starved: %d", response.Code)
	}
	if response := callHandler(handler, http.MethodGet, "/api/v1/status", "", withMaster()); response.Code != http.StatusOK {
		t.Fatalf("master was starved: %d", response.Code)
	}
}

type leakySettingsMHX struct {
	*fixedMHX
	err error
}

func (l *leakySettingsMHX) PolicySettings() mhx.PolicySettings { return mhx.PolicySettings{} }

func (l *leakySettingsMHX) SetPolicySettings(context.Context, mhx.PolicySettingsPatch) (mhx.PolicySettings, error) {
	return mhx.PolicySettings{}, l.err
}

func TestEngineErrorsNeverReachTheClient(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaky := &leakySettingsMHX{
		fixedMHX: &fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true}},
		err:      fmt.Errorf("open C:\\ProgramData\\VGT\\GeDefense\\secret-token.db: access denied"),
	}
	_, handler := newServer("test", testMasterToken, fixedEngine{}, fixedAudit{}, fixedXDR{}, leaky, &fixedIntegrity{}, ledger, nil, nil, nil)
	body := `{"aggressiveness":{"process":"guarded"},"reason":"operator changes XDR policy"}`
	response := callHandler(handler, http.MethodPost, "/api/v1/mhx/settings", body, withMaster(), withReplayID())
	if response.Code != http.StatusConflict {
		t.Fatalf("engine rejection status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "ProgramData") || strings.Contains(response.Body.String(), "secret-token") || strings.Contains(response.Body.String(), "access denied") {
		t.Fatalf("engine error detail leaked to client: %s", response.Body.String())
	}
	payload := decodeBody(t, response)
	if payload["errorId"] == "" || payload["error"] == "" {
		t.Fatalf("opaque error response incomplete: %v", payload)
	}

	leakyKinetic := &leakyKineticMHX{
		fixedMHX: &fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true}},
		err:      fmt.Errorf("write C:\\ProgramData\\VGT\\GeDefense\\kinetic-secret.json: access denied"),
	}
	_, kineticHandler := newServer("test", testMasterToken, fixedEngine{}, fixedAudit{}, fixedXDR{}, leakyKinetic, &fixedIntegrity{}, ledger, nil, nil, nil)
	kineticBody := `{"armedAfterRestart":true,"reason":"operator arms kinetic persistence"}`
	kineticResponse := callHandler(kineticHandler, http.MethodPost, "/api/v1/kinetic/settings", kineticBody, withMaster(), withReplayID())
	if kineticResponse.Code != http.StatusConflict {
		t.Fatalf("kinetic engine rejection status=%d body=%s", kineticResponse.Code, kineticResponse.Body.String())
	}
	if strings.Contains(kineticResponse.Body.String(), "ProgramData") || strings.Contains(kineticResponse.Body.String(), "kinetic-secret") || strings.Contains(kineticResponse.Body.String(), "access denied") {
		t.Fatalf("kinetic engine error detail leaked to client: %s", kineticResponse.Body.String())
	}
	if decodeBody(t, kineticResponse)["errorId"] == "" {
		t.Fatal("kinetic rejection is missing an error id")
	}
}

// leakyKineticMHX returns a raw error from the desired-state transition so the
// handler must not forward it (AN-FIND-009).
type leakyKineticMHX struct {
	*fixedMHX
	err      error
	snapshot mhx.KineticSettingsSnapshot
}

func (l *leakyKineticMHX) KineticSettings() mhx.KineticSettingsSnapshot {
	if l.snapshot.SchemaVersion == 0 {
		l.snapshot = mhx.KineticSettingsSnapshot{SchemaVersion: 1, Config: kinetic.DefaultConfig()}
	}
	return l.snapshot
}

func (l *leakyKineticMHX) SetKineticConfig(_ context.Context, config kinetic.Config) (mhx.KineticSettingsSnapshot, error) {
	l.snapshot = mhx.KineticSettingsSnapshot{SchemaVersion: 1, Config: config}
	return l.snapshot, nil
}

func (l *leakyKineticMHX) SetKineticDesiredState(context.Context, bool) (mhx.KineticSettingsSnapshot, error) {
	return l.snapshot, l.err
}

func TestPolicyAttributionIsRecordedForScopedClients(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, handler := newServer("test", testMasterToken, fixedEngine{}, fixedAudit{}, fixedXDR{},
		&fixedMHX{mode: "monitor", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{}, ledger, nil, nil, nil)
	policySession := mintSession(t, handler, "admin-service", "read", "operate", "policy")
	response := callHandler(handler, http.MethodPost, "/api/v1/hardening/rollback",
		`{"confirmation":"ROLLBACK HARDENING","reason":"operator requested rollback for attribution test"}`,
		withBearer(policySession), withReplayID())
	if response.Code != http.StatusOK {
		t.Fatalf("policy mutation status=%d body=%s", response.Code, response.Body.String())
	}
	records, err := ledger.Snapshot(200)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Kind == "authorization.policy" && record.Action == "/api/v1/hardening/rollback" && strings.Contains(record.Result, "client=admin-service") {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy attribution missing from evidence ledger: %+v", records)
	}
}

func TestScopedSessionCannotUseMasterAdministrativeRoutes(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	sessionToken := mintSession(t, handler, "admin-service", "read", "operate", "policy")
	for _, path := range []string{"/api/v1/admin/sessions/revoke-all", "/api/v1/admin/token/rotate", "/api/v1/session/bootstrap"} {
		response := callHandler(handler, http.MethodPost, path, "{}", withBearer(sessionToken), withReplayID())
		if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
			t.Fatalf("%s accepted a scoped session: %d %s", path, response.Code, response.Body.String())
		}
	}
}

func TestBrowserExchangeRequiresOriginAndRegistration(t *testing.T) {
	server, handler := newSecurityTestServer(t)
	server.peerPID = func(string) (uint32, error) { return 4242, nil }
	register := callHandler(handler, http.MethodPost, "/api/v1/session/register-browser", `{"pid":4242}`, withMaster(), withReplayID())
	if register.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", register.Code, register.Body.String())
	}
	withoutOrigin := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}", withReplayID())
	if withoutOrigin.Code != http.StatusForbidden {
		t.Fatalf("exchange without origin status=%d", withoutOrigin.Code)
	}
	accepted := callHandler(handler, http.MethodPost, "/api/v1/session/exchange", "{}", withOrigin("http://127.0.0.1:17831"), withReplayID())
	if accepted.Code != http.StatusOK || len(accepted.Result().Cookies()) != 1 {
		t.Fatalf("exchange with origin status=%d body=%s", accepted.Code, accepted.Body.String())
	}
}
