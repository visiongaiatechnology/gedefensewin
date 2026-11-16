// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/security"
)

type authContextKey struct{}

func withAuthContext(r *http.Request, auth authContext) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authContextKey{}, auth))
}

func authContextFrom(r *http.Request) (authContext, bool) {
	auth, ok := r.Context().Value(authContextKey{}).(authContext)
	return auth, ok
}

// bootstrap issues a one-time bootstrap code for the legacy code exchange. The
// production Center no longer transports this code on a process command line
// (AN-FIND-002); it is kept as an explicitly authorized compatibility path for
// master-authenticated local tooling and is revoked together with all sessions.
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	now := s.clock()
	code, err := randomCredential()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session initialization failed")
		return
	}
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	if len(s.bootstrapCodes) >= maxBootstrapEntries {
		s.sessionMu.Unlock()
		s.writeError(w, http.StatusTooManyRequests, "session initialization rate limited")
		return
	}
	s.bootstrapCodes[code] = bootstrapCode{expires: now.Add(bootstrapCodeLifetime), scopes: scopeAll, client: "center"}
	s.sessionMu.Unlock()
	s.writeJSON(w, http.StatusCreated, map[string]string{"code": code})
}

// registerBrowser records the short-lived expectation that ownerPID (the exact
// Chromium process the launcher started) will perform one session exchange. The
// exchange itself is then bound to the operating-system peer process, so no
// bearer secret has to travel through the browser command line.
func (s *Server) registerBrowser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PID             uint32 `json:"pid"`
		Client          string `json:"client"`
		LifetimeSeconds int    `json:"lifetimeSeconds"`
	}
	if err := decodeJSON(w, r, &input); err != nil || input.PID == 0 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	client := strings.TrimSpace(input.Client)
	if client == "" {
		client = "center"
	}
	if !validClientName(client) {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	lifetime := browserRegistrationTTL
	if input.LifetimeSeconds != 0 {
		lifetime = time.Duration(input.LifetimeSeconds) * time.Second
	}
	if lifetime < 10*time.Second || lifetime > 2*time.Minute {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	now := s.clock()
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	// Registrations are unique per (pid, client): a repeated registration for the
	// same launcher child replaces the previous expectation instead of leaving an
	// ambiguous duplicate behind (FIND-WIN-020).
	retained := s.browserRegistrations[:0]
	for _, existing := range s.browserRegistrations {
		if existing.pid == input.PID && existing.client == client {
			continue
		}
		retained = append(retained, existing)
	}
	s.browserRegistrations = retained
	if len(s.browserRegistrations) >= maxBrowserRegistrations {
		s.sessionMu.Unlock()
		s.writeError(w, http.StatusTooManyRequests, "browser registration rate limited")
		return
	}
	s.browserRegistrations = append(s.browserRegistrations, browserRegistration{
		pid: input.PID, expires: now.Add(lifetime), scopes: scopeAll, client: client,
	})
	s.sessionMu.Unlock()
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"registered": true, "client": client, "expiresUtc": now.Add(lifetime).UTC(),
	})
}

func validClientName(client string) bool {
	if len(client) < 3 || len(client) > 64 {
		return false
	}
	for _, character := range client {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-', character == '_', character == '.':
		default:
			return false
		}
	}
	return true
}

// exchange upgrades either a one-time bootstrap code (legacy, master-authorized
// issuance) or a registered browser process into a server-side session. The
// browser path additionally verifies that the loopback peer of this very
// request belongs to the process the launcher registered. The code is never
// written to the browser command line by this product.
//
// Ordering contract (FIND-WIN-007): the public endpoint has its own attempt
// budget, and the replay guard is consumed only after the request presented a
// credential (bootstrap code) or was bound to the registered peer process.
// Unauthenticated floods therefore never occupy the bounded replay table and
// cannot deny legitimate mutations with HTTP 409.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r, false) {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	// Dedicated public bootstrap budget: a bogus Authorization header must not
	// bypass abuse protection (the outer wrapper only counts requests without any
	// credential material).
	remoteHost := remoteHostOf(r)
	if !s.allowRate("exchange:"+remoteHost, rateBootstrap) {
		w.Header().Set("Retry-After", "5")
		s.writeError(w, http.StatusTooManyRequests, "request rate limited")
		return
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	now := s.clock()
	code := strings.TrimSpace(input.Code)
	if code != "" {
		// Possession of a live bootstrap code is the credential. Validate it
		// before consuming a replay slot and before deleting the one-time code:
		// a rejected replay must not burn a valid bootstrap authorization.
		s.sessionMu.Lock()
		s.purgeSessionsLocked(now)
		record, exists := s.bootstrapCodes[code]
		s.sessionMu.Unlock()
		if !exists || now.After(record.expires) {
			s.writeError(w, http.StatusUnauthorized, "bootstrap code rejected")
			return
		}
		if !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		s.sessionMu.Lock()
		s.purgeSessionsLocked(now)
		record, exists = s.bootstrapCodes[code]
		if !exists || now.After(record.expires) {
			s.sessionMu.Unlock()
			s.writeError(w, http.StatusUnauthorized, "bootstrap code rejected")
			return
		}
		delete(s.bootstrapCodes, code)
		token, recordSession, err := s.createSessionLocked(now, record.client, record.scopes, sessionAbsoluteLifetime)
		s.sessionMu.Unlock()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "session initialization failed")
			return
		}
		s.setSessionCookie(w, token, recordSession.expires)
		s.auditSession("created:bootstrap-code", recordSession.client, recordSession.scopes, token)
		s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
		return
	}
	// Browser path: snapshot every pending registration (the whole bounded slice,
	// not just the newest entry) and bind it to the operating-system peer of this
	// very connection before any replay slot is consumed.
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	pending := s.pendingBrowserRegistrationLocked(now)
	s.sessionMu.Unlock()
	if len(pending) == 0 {
		// The launcher registers the browser immediately after process start. A
		// page that loads faster than that registration must retry; it never
		// receives an unauthenticated session.
		s.writeError(w, http.StatusUnauthorized, "browser session not authorized")
		return
	}
	peerPID, err := s.peerProcessID(r.RemoteAddr)
	if err != nil || peerPID == 0 {
		s.writeError(w, http.StatusUnauthorized, "browser session not authorized")
		return
	}
	var matched *browserRegistration
	for index := range pending {
		if browserPeerMatchesPID(peerPID, pending[index].pid) {
			matched = &pending[index]
			break
		}
	}
	if matched == nil {
		s.writeError(w, http.StatusUnauthorized, "browser session not authorized")
		return
	}
	// The request is bound to the registered peer process now; only here does a
	// replay slot get consumed. A failed replay leaves the registration intact so
	// the operator can retry with a fresh request id.
	if !s.claim(r.Header.Get("X-VGT-Request-ID")) {
		s.writeError(w, http.StatusConflict, "request rejected")
		return
	}
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	if !s.consumeBrowserRegistrationLocked(*matched) {
		s.sessionMu.Unlock()
		s.writeError(w, http.StatusUnauthorized, "browser session not authorized")
		return
	}
	token, recordSession, err := s.createSessionLocked(now, matched.client, matched.scopes, sessionAbsoluteLifetime)
	s.sessionMu.Unlock()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session initialization failed")
		return
	}
	s.setSessionCookie(w, token, recordSession.expires)
	s.auditSession("created:browser-process", recordSession.client, recordSession.scopes, token)
	s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func sameRegistration(left, right browserRegistration) bool {
	return left.pid == right.pid && left.expires.Equal(right.expires) && left.client == right.client
}

// pendingBrowserRegistrationLocked returns every unexpired registration as a
// copy. Callers must match the list against the verified peer process instead of
// trusting the newest entry, so a registration from another window does not mask
// the one that actually owns this connection (FIND-WIN-020). The returned slice
// is bounded by maxBrowserRegistrations. The caller holds sessionMu.
func (s *Server) pendingBrowserRegistrationLocked(now time.Time) []browserRegistration {
	pending := make([]browserRegistration, 0, len(s.browserRegistrations))
	for _, registration := range s.browserRegistrations {
		if now.Before(registration.expires) {
			pending = append(pending, registration)
		}
	}
	return pending
}

// consumeBrowserRegistrationLocked removes exactly the registration that was
// verified against the peer process. The caller holds sessionMu.
func (s *Server) consumeBrowserRegistrationLocked(verified browserRegistration) bool {
	for index, registration := range s.browserRegistrations {
		if !sameRegistration(registration, verified) {
			continue
		}
		s.browserRegistrations = append(s.browserRegistrations[:index], s.browserRegistrations[index+1:]...)
		return true
	}
	return false
}

// browserPeerMatchesPID reports whether the verified loopback peer is the
// registered browser process itself or a descendant of it (Chromium spawns
// helper processes that may carry the socket). Both sides must be concrete
// process ids; a zero pid never matches.
func browserPeerMatchesPID(peerPID, expectedPID uint32) bool {
	if peerPID == 0 || expectedPID == 0 {
		return false
	}
	if peerPID == expectedPID {
		return true
	}
	return processDescendsFrom(peerPID, expectedPID)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	// Secure=false is required because the control plane is loopback HTTP. The
	// cookie is HttpOnly, SameSite=Strict and not shared across any origin; the
	// local admin traffic-sniffing threat is documented as residual risk.
	http.SetCookie(w, &http.Cookie{
		Name: "VGTSESSION", Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "VGTSESSION", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (s *Server) newSessionToken() (string, error) {
	body, err := randomCredential()
	if err != nil {
		return "", err
	}
	return sessionIDPrefix + body, nil
}

// createSessionLocked registers a new session. The caller holds sessionMu.
func (s *Server) createSessionLocked(now time.Time, client string, scopes scope, lifetime time.Duration) (string, *sessionRecord, error) {
	if client == "" {
		client = "center"
	}
	if scopes == 0 {
		scopes = scopeRead
	}
	if lifetime <= 0 {
		lifetime = sessionAbsoluteLifetime
	}
	for len(s.sessions) >= maxSessionEntries*2 {
		// Map may contain one previous-grace alias per session; when even that is
		// full the oldest idle session is evicted (never the master credential).
		if !s.evictOldestSessionLocked(now) {
			return "", nil, errors.New("session capacity exhausted")
		}
	}
	token, err := s.newSessionToken()
	if err != nil {
		return "", nil, err
	}
	record := &sessionRecord{
		token: token, client: client, scopes: scopes,
		issuedAt: now, expires: now.Add(lifetime), idleExpires: now.Add(sessionIdleLifetime),
	}
	s.sessions[token] = record
	return token, record, nil
}

func (s *Server) evictOldestSessionLocked(now time.Time) bool {
	var oldestToken string
	var oldestIssue time.Time
	for token, record := range s.sessions {
		if token != record.token {
			continue
		}
		if oldestToken == "" || record.issuedAt.Before(oldestIssue) {
			oldestToken, oldestIssue = token, record.issuedAt
		}
	}
	if oldestToken == "" {
		return false
	}
	s.dropSessionLocked(oldestToken)
	return true
}

func (s *Server) dropSessionLocked(token string) {
	record, ok := s.sessions[token]
	if !ok {
		return
	}
	delete(s.sessions, token)
	if record.token != token {
		delete(s.sessions, record.token)
	}
	if record.previousToken != "" {
		delete(s.sessions, record.previousToken)
	}
}

// authenticate resolves the master file credential (full authority) or a
// server-side session (scoped authority). Cookie sessions are rotated when due;
// the old token stays valid for a short grace window so concurrent browser
// requests do not race the rotation.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (authContext, bool) {
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if security.TokenEqual(provided, s.masterToken()) {
		return authContext{master: true, scopes: scopeAll, client: "master"}, true
	}
	token := provided
	viaCookie := false
	if !strings.HasPrefix(token, sessionIDPrefix) {
		cookie, err := r.Cookie("VGTSESSION")
		if err != nil || !strings.HasPrefix(cookie.Value, sessionIDPrefix) {
			return authContext{}, false
		}
		token = cookie.Value
		viaCookie = true
	}
	now := s.clock()
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	record, exists := s.sessions[token]
	if !exists || record == nil {
		s.sessionMu.Unlock()
		return authContext{}, false
	}
	if record.token != token {
		if record.previousToken != token || now.After(record.previousValidUntil) {
			s.sessionMu.Unlock()
			return authContext{}, false
		}
	}
	if now.After(record.expires) || now.After(record.idleExpires) {
		s.dropSessionLocked(record.token)
		s.sessionMu.Unlock()
		return authContext{}, false
	}
	record.idleExpires = now.Add(sessionIdleLifetime)
	if viaCookie && now.Sub(record.issuedAt) >= sessionRotationInterval {
		s.rotateSessionLocked(now, record)
		s.sessionMu.Unlock()
		s.setSessionCookie(w, record.token, record.expires)
		return authContext{session: record, token: record.token, client: record.client, scopes: record.scopes, viaCookie: true, expires: record.expires, idleExpires: record.idleExpires}, true
	}
	currentToken := record.token
	expires := record.expires
	idleExpires := record.idleExpires
	s.sessionMu.Unlock()
	return authContext{session: record, token: currentToken, client: record.client, scopes: record.scopes, viaCookie: viaCookie, expires: expires, idleExpires: idleExpires}, true
}

func (s *Server) rotateSessionLocked(now time.Time, record *sessionRecord) {
	replacement, err := s.newSessionToken()
	if err != nil {
		return
	}
	oldToken := record.token
	delete(s.sessions, oldToken)
	record.previousToken = oldToken
	record.previousValidUntil = now.Add(sessionRotationGrace)
	record.token = replacement
	record.issuedAt = now
	s.sessions[replacement] = record
	s.sessions[oldToken] = record
}

func (s *Server) purgeSessionsLocked(now time.Time) {
	for code, record := range s.bootstrapCodes {
		if now.After(record.expires) {
			delete(s.bootstrapCodes, code)
		}
	}
	live := s.browserRegistrations[:0]
	for _, registration := range s.browserRegistrations {
		if now.Before(registration.expires) {
			live = append(live, registration)
		}
	}
	s.browserRegistrations = live
	for token, record := range s.sessions {
		if record == nil || now.After(record.expires) {
			delete(s.sessions, token)
			continue
		}
		if token != record.token && now.After(record.previousValidUntil) {
			delete(s.sessions, token)
		}
	}
}

// sessionLogout revokes the authenticated session and expires the cookie. The
// master credential is not a session and cannot be logged out; rotating the
// token file is the break-glass revocation for it.
func (s *Server) sessionLogout(w http.ResponseWriter, r *http.Request) {
	auth, ok := authContextFrom(r)
	if !ok || auth.master || auth.session == nil {
		s.clearSessionCookie(w)
		s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	now := s.clock()
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	s.dropSessionLocked(auth.token)
	if auth.session.token != auth.token {
		s.dropSessionLocked(auth.session.token)
	}
	s.sessionMu.Unlock()
	s.clearSessionCookie(w)
	s.auditSession("revoked:logout", auth.client, auth.scopes, auth.token)
	s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

// sessionState reports the authenticated client, scopes and remaining lifetime
// so the UI can display and enforce its own session semantics.
func (s *Server) sessionState(w http.ResponseWriter, r *http.Request) {
	auth, ok := authContextFrom(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "authorization required")
		return
	}
	payload := map[string]any{
		"authenticated": true, "client": auth.client, "scopes": auth.scopeNames(),
		"master": auth.master,
	}
	if auth.session != nil {
		payload["expiresUtc"] = auth.expires.UTC()
		payload["idleExpiresUtc"] = auth.idleExpires.UTC()
		if auth.session.operator {
			payload["operator"] = true
			payload["subject"] = map[string]any{
				"account": auth.session.subjectAccount,
			}
		}
	}
	s.writeJSON(w, http.StatusOK, payload)
}

// adminCreateSession mints a narrowly scoped bearer session for a trusted local
// client (for example the window host). This is the local, dependency-free
// replacement for one shared service credential (AN-FIND-004).
func (s *Server) adminCreateSession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Client          string   `json:"client"`
		Scopes          []string `json:"scopes"`
		LifetimeSeconds int      `json:"lifetimeSeconds"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	client := strings.TrimSpace(input.Client)
	if !validClientName(client) {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	scopes, ok := normaliseScopeList(input.Scopes)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	lifetime := defaultServiceLifetime
	if input.LifetimeSeconds != 0 {
		lifetime = time.Duration(input.LifetimeSeconds) * time.Second
	}
	if lifetime < minSessionLifetime || lifetime > maxSessionTokensPerAdmin*time.Second {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	now := s.clock()
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	token, record, err := s.createSessionLocked(now, client, scopes, lifetime)
	s.sessionMu.Unlock()
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "session initialization failed")
		return
	}
	s.auditSession("created:scoped-service", client, scopes, token)
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "client": client, "scopes": scopes.names(), "expiresUtc": record.expires.UTC(),
	})
}

// revokeAllSessions drops every browser/service session and every pending
// bootstrap authorization. It is the incident-response switch for a leaked
// session cookie (AN-FIND-003/UI-FIND-005).
func (s *Server) revokeAllSessions(w http.ResponseWriter, _ *http.Request) {
	s.sessionMu.Lock()
	revoked := 0
	for key, record := range s.sessions {
		if record != nil && key == record.token {
			revoked++
		}
		delete(s.sessions, key)
	}
	s.bootstrapCodes = make(map[string]bootstrapCode)
	s.browserRegistrations = nil
	s.sessionMu.Unlock()
	s.auditSession("revoked:all", "master", scopeAll, "")
	s.writeJSON(w, http.StatusOK, map[string]any{"revokedSessions": revoked})
}

// sessionDigest is used for audit-friendly, non-secret session references.
func sessionDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// auditSession records a non-secret session lifecycle event in the evidence
// chain so credential use is attributable to a client identity (AN-FIND-004).
func (s *Server) auditSession(event, client string, scopes scope, token string) {
	if s.ledger == nil {
		return
	}
	detail := event + "; scopes=" + strings.Join(scopes.names(), ",")
	if token != "" {
		detail += "; session=" + sessionDigest(token)
	}
	if err := s.ledger.Append("session.lifecycle", client, detail); err != nil {
		log.Printf("session evidence: %v", err)
	}
}
