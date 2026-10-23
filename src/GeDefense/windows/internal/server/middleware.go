// STATUS: DIAMANT VGT SUPREME
package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	maxPolicyIntentBody = 64 << 10
	// maxUnauthenticatedRequestsPerMinute is the global brake for clients that
	// present no credential at all. Authenticated scopes have their own budgets.
	maxUnauthenticatedRequestsPerMinute = 300
)

// headers is the outermost wrapper. Security headers are applied before any
// rejection so that even early 400/403/429 responses carry the full header set
// and are never cacheable (AN-FIND-008).
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

		host, port, err := net.SplitHostPort(r.Host)
		if err != nil || port != "17831" || (host != "127.0.0.1" && !strings.EqualFold(host, "localhost")) {
			s.writeError(w, http.StatusBadRequest, "request rejected")
			return
		}
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || (remoteHost != "127.0.0.1" && remoteHost != "::1") {
			s.writeError(w, http.StatusForbidden, "request rejected")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !hasCredentialMaterial(r) {
			if !s.allowRate("anon:"+remoteHost, rateRead) {
				w.Header().Set("Retry-After", "5")
				s.writeError(w, http.StatusTooManyRequests, "request rate limited")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func hasCredentialMaterial(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return true
	}
	_, err := r.Cookie("VGTSESSION")
	return err == nil
}

type routeAuthMode int

const (
	authRead routeAuthMode = iota
	authOperate
	authPolicy
	authWindow
	authMaster
)

// protected wraps a route with authentication, origin/replay protection, scope
// enforcement and class-based rate limiting. When confirmation is non-empty the
// route additionally requires a typed confirmation phrase and an operator
// reason in the JSON body (AN-FIND-005/UI-FIND-003): security-reducing
// mutations cannot be executed by a bare authenticated POST.
func (s *Server) protected(mode routeAuthMode, confirmation string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth, ok := s.authenticate(w, r)
		if !ok {
			s.rejectUnauthenticated(w, r)
			return
		}
		if mode == authMaster && !auth.master {
			s.writeError(w, http.StatusForbidden, "insufficient authorization")
			return
		}
		if !s.requestOriginAllowed(r, auth) {
			s.writeError(w, http.StatusForbidden, "request rejected")
			return
		}
		required := scope(0)
		if !auth.master {
			required = requiredScope(mode)
			if !auth.scopes.has(required) {
				s.writeError(w, http.StatusForbidden, "insufficient authorization")
				return
			}
		}
		// Rate budgets are checked before the replay guard so a caller cannot
		// exhaust the replay table and deny legitimate mutations.
		if !s.allowRate(auth.identity(), rateClassForRoute(mode, r.Method, r.URL.Path)) {
			w.Header().Set("Retry-After", "5")
			s.writeError(w, http.StatusTooManyRequests, "request rate limited")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		reason := ""
		if confirmation != "" {
			var allowed bool
			reason, allowed = s.requirePolicyIntent(w, r, confirmation)
			if !allowed {
				return
			}
		}
		if mode == authPolicy {
			s.recordPolicyAttribution(auth, r, reason)
		}
		next(w, withAuthContext(r, auth))
	}
}

// rejectUnauthenticated applies the anonymous budget even when a bogus
// credential was supplied, so invalid cookies/tokens cannot bypass abuse
// protection by making hasCredentialMaterial true. Requests without any
// credential material were already counted by the outer headers wrapper and
// are not counted twice.
func (s *Server) rejectUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if hasCredentialMaterial(r) {
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}
		if !s.allowRate("anon:"+remoteHost, rateRead) {
			w.Header().Set("Retry-After", "5")
			s.writeError(w, http.StatusTooManyRequests, "request rate limited")
			return
		}
	}
	s.writeError(w, http.StatusUnauthorized, "authorization required")
}

// recordPolicyAttribution adds a non-secret audit record for every policy-class
// mutation: which scoped client exercised which resource with which confirmed
// intent (AN-FIND-001/004). Details stay in the HMAC evidence ledger.
func (s *Server) recordPolicyAttribution(auth authContext, r *http.Request, reason string) {
	if s.ledger == nil {
		return
	}
	detail := "client=" + auth.client + "; scopes=" + strings.Join(auth.scopes.names(), ",")
	if auth.session != nil {
		detail += "; session=" + sessionDigest(auth.token)
	}
	if reason != "" {
		digest := sha256.Sum256([]byte(strings.TrimSpace(reason)))
		detail += "; reason-sha256=" + hex.EncodeToString(digest[:])
	}
	if err := s.ledger.Append("authorization.policy", r.URL.Path, detail); err != nil {
		log.Printf("policy attribution evidence: %v", err)
	}
}

func requiredScope(mode routeAuthMode) scope {
	switch mode {
	case authRead:
		return scopeRead
	case authOperate:
		return scopeOperate
	case authPolicy:
		return scopePolicy
	case authWindow:
		return scopeWindow
	default:
		return scopeAll
	}
}

func rateClassForRoute(mode routeAuthMode, method, path string) rateClass {
	if isLongOperation(method, path) {
		return rateLong
	}
	switch mode {
	case authRead:
		return rateRead
	case authWindow:
		// The window host polls once per second and acknowledges state separately;
		// long-poll GETs therefore use the read budget, mutations the operate one.
		if method == http.MethodGet || method == http.MethodHead {
			return rateRead
		}
		return rateOperate
	case authPolicy, authMaster:
		return ratePolicy
	default:
		return rateOperate
	}
}

func isLongOperation(method, path string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return false
	}
	switch path {
	case "/api/v1/health/refresh", "/api/v1/audit/run", "/api/v1/xdr/scan",
		"/api/v1/mhx/feeds/sync", "/api/v1/mhx/policy/reconcile",
		"/api/v1/hardening/enforce", "/api/v1/hardening/rollback",
		"/api/v1/hardening/settings", "/api/v1/hardening/components",
		"/api/v1/settings", "/api/v1/settings/profiles",
		"/api/v1/integrity/scan", "/api/v1/session/exchange",
		"/api/v1/session/bootstrap", "/api/v1/session/register-browser":
		return true
	}
	return false
}

func rateLimitFor(class rateClass, identity string) int {
	master := identity == "master"
	session := strings.HasPrefix(identity, "session:")
	switch class {
	case rateRead:
		if master {
			return 1200
		}
		if session {
			return 600
		}
		return maxUnauthenticatedRequestsPerMinute
	case rateOperate:
		if master {
			return 600
		}
		return 120
	case ratePolicy:
		if master {
			return 30
		}
		return 10
	case rateLong:
		if master {
			return 6
		}
		return 2
	default:
		return 60
	}
}

// allowRate applies a per-identity, per-class fixed window budget. The master
// credential is rate limited as well (higher budget), never exempted
// (AN-FIND-006). Windows are one minute and expire lazily.
func (s *Server) allowRate(identity string, class rateClass) bool {
	now := s.clock()
	limit := rateLimitFor(class, identity)
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	for key, bucket := range s.rates {
		if now.Sub(bucket.lastSeen) >= 2*time.Minute {
			delete(s.rates, key)
		}
	}
	bucket, exists := s.rates[identity]
	if !exists {
		if len(s.rates) >= maxRateEntries {
			return false
		}
		bucket = &rateBucket{started: now, counts: make(map[rateClass]int)}
		s.rates[identity] = bucket
	}
	if now.Sub(bucket.started) >= time.Minute {
		bucket.started = now
		bucket.counts = make(map[rateClass]int)
	}
	bucket.lastSeen = now
	if bucket.counts[class] >= limit {
		return false
	}
	bucket.counts[class]++
	return true
}

// requirePolicyIntent validates the typed confirmation phrase and the operator
// reason of a security-reducing mutation before any handler sees the request.
// The original body is restored for the handler (which may strictly decode its
// own schema). It returns the validated reason and false after writing the
// rejection when the intent is not acceptable.
func (s *Server) requirePolicyIntent(w http.ResponseWriter, r *http.Request, phrase string) (string, bool) {
	var envelope struct {
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if r.Body == nil || !contentTypeJSON(r) {
		s.writeError(w, http.StatusBadRequest, "explicit confirmation and reason required")
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyIntentBody+1))
	if err != nil || len(body) > maxPolicyIntentBody {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return "", false
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		s.writeError(w, http.StatusBadRequest, "explicit confirmation and reason required")
		return "", false
	}
	if strings.TrimSpace(envelope.Confirmation) != phrase {
		s.writeError(w, http.StatusConflict, "explicit confirmation required")
		return "", false
	}
	if validateReason(envelope.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return strings.TrimSpace(envelope.Reason), true
}

func (s *Server) masterAuthorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth, ok := s.authenticate(w, r)
		if !ok || !auth.master {
			s.rejectUnauthenticated(w, r)
			return
		}
		if !s.requestOriginAllowed(r, auth) {
			s.writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		if !s.allowRate("master", rateClassForRoute(authMaster, r.Method, r.URL.Path)) {
			w.Header().Set("Retry-After", "5")
			s.writeError(w, http.StatusTooManyRequests, "request rate limited")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		next(w, withAuthContext(r, auth))
	}
}

// windowAuthorize accepts either the master break-glass credential or a scoped
// window-host session (bearer). The launcher mints the scoped session so the
// shared file credential is no longer the every-window-poll identity
// (AN-FIND-004).
func (s *Server) windowAuthorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth, ok := s.authenticate(w, r)
		if !ok {
			s.rejectUnauthenticated(w, r)
			return
		}
		if !auth.master && !auth.scopes.has(scopeWindow) {
			s.writeError(w, http.StatusForbidden, "insufficient authorization")
			return
		}
		if !s.requestOriginAllowed(r, auth) {
			s.writeError(w, http.StatusForbidden, "request rejected")
			return
		}
		if !s.allowRate(auth.identity(), rateClassForRoute(authWindow, r.Method, r.URL.Path)) {
			w.Header().Set("Retry-After", "5")
			s.writeError(w, http.StatusTooManyRequests, "request rate limited")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		next(w, withAuthContext(r, auth))
	}
}

// operatorAuthorize accepts either the master break-glass credential or an
// operator session minted by the OS-identity broker (the caller's Windows token
// proved operator-group/Administrators membership). Browser cookie sessions and
// generic service sessions never pass this wrapper; it is only used for the
// privileged window registration step that binds a browser child process
// (UI-FIND-001 / AN-FIND-004).
func (s *Server) operatorAuthorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth, ok := s.authenticate(w, r)
		if !ok {
			s.rejectUnauthenticated(w, r)
			return
		}
		if !auth.master {
			if auth.session == nil || !auth.session.operator || !auth.scopes.has(scopeAll) {
				s.writeError(w, http.StatusForbidden, "insufficient authorization")
				return
			}
		}
		if !s.requestOriginAllowed(r, auth) {
			s.writeError(w, http.StatusForbidden, "request rejected")
			return
		}
		if !s.allowRate(auth.identity(), rateClassForRoute(authOperate, r.Method, r.URL.Path)) {
			w.Header().Set("Retry-After", "5")
			s.writeError(w, http.StatusTooManyRequests, "request rate limited")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		next(w, withAuthContext(r, auth))
	}
}

// requestOriginAllowed protects cookie-authenticated mutations against
// cross-origin requests. The master credential and bearer service sessions are
// non-browser clients and may omit Origin; a cookie session must always present
// the exact loopback origin for a mutation, matching the browser's SameSite
// cookie policy.
func (s *Server) requestOriginAllowed(r *http.Request, auth authContext) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if auth.master || !auth.viaCookie {
			return true
		}
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	}
	return subtle.ConstantTimeCompare([]byte(origin), []byte("http://"+r.Host)) == 1
}

// originAllowed is the public (unauthenticated) origin check used by the
// session exchange endpoint.
func (s *Server) originAllowed(r *http.Request, master bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return master || r.Method == http.MethodGet || r.Method == http.MethodHead
	}
	return subtle.ConstantTimeCompare([]byte(origin), []byte("http://"+r.Host)) == 1
}

func randomCredential() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func contentTypeJSON(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func validRequestID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index, character := range id {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < 'a' || character > 'f') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

// claim enforces the X-VGT-Request-ID replay guard for mutations. This is shared
// by every wrapper (session, master and window) so a POST can never bypass the
// replay protection by choosing a different authentication path (AN-FIND-007).
func (s *Server) claim(id string) bool {
	if !validRequestID(id) {
		return false
	}
	now := s.clock()
	s.replay.mu.Lock()
	defer s.replay.mu.Unlock()
	for key, expiry := range s.replay.items {
		if now.After(expiry) {
			delete(s.replay.items, key)
		}
	}
	if _, exists := s.replay.items[id]; exists || len(s.replay.items) >= maxReplayEntries {
		return false
	}
	s.replay.items[id] = now.Add(10 * time.Minute)
	return true
}

func validateReason(reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return errors.New("reason boundary rejected")
	}
	return nil
}
