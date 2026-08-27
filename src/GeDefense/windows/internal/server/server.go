// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/security"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

//go:embed web/*
var assets embed.FS

type replayGuard struct {
	mu    sync.Mutex
	items map[string]time.Time
}

type rateWindow struct {
	started time.Time
	count   int
}

type Server struct {
	version        string
	token          string
	engine         HardeningEngine
	audit          AuditEngine
	xdr            XDREngine
	mhx            MHXEngine
	integrity      IntegrityEngine
	ledger         *evidence.Ledger
	replay         replayGuard
	sessionMu      sync.Mutex
	bootstrapCodes map[string]time.Time
	sessions       map[string]time.Time
	rateMu         sync.Mutex
	rates          map[string]rateWindow
}

type HardeningEngine interface {
	Audit(context.Context) (hardening.Result, error)
	Enforce(context.Context, string) (hardening.Result, error)
	Components(context.Context) ([]hardening.ComponentStatus, error)
	EnforceComponent(context.Context, string) ([]hardening.ComponentStatus, error)
	Rollback(context.Context) (hardening.Result, error)
}

type AuditEngine interface {
	Run(context.Context) (audit.Result, error)
}

type XDREngine interface {
	Scan(context.Context) (xdr.Result, error)
	Last() xdr.Result
}

type MHXEngine interface {
	Status() mhx.Status
	Analyses(int) []mhx.Analysis
	SetMode(string) error
	SyncFeeds(context.Context) error
	Applications(context.Context) ([]mhx.ApplicationAllow, error)
	SetApplication(context.Context, string, string) ([]mhx.ApplicationAllow, error)
}

type IntegrityEngine interface {
	Status() integrity.Status
	Configure(bool, int) (integrity.Status, error)
	Start() error
	Changes(int, int) ([]integrity.Change, error)
}

func New(version, token string, engine HardeningEngine, auditEngine AuditEngine, xdrEngine XDREngine, mhxEngine MHXEngine, integrityEngine IntegrityEngine, ledger *evidence.Ledger) http.Handler {
	s := &Server{version: version, token: token, engine: engine, audit: auditEngine, xdr: xdrEngine, mhx: mhxEngine, integrity: integrityEngine, ledger: ledger, replay: replayGuard{items: make(map[string]time.Time)}, bootstrapCodes: make(map[string]time.Time), sessions: make(map[string]time.Time), rates: make(map[string]rateWindow)}
	mux := http.NewServeMux()
	webRoot, _ := fs.Sub(assets, "web")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(webRoot))))
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("POST /api/v1/session/bootstrap", s.masterAuthorize(s.bootstrap))
	mux.HandleFunc("POST /api/v1/session/exchange", s.exchange)
	mux.HandleFunc("GET /api/v1/status", s.authorize(s.status))
	mux.HandleFunc("GET /api/v1/evidence", s.authorize(s.evidence))
	mux.HandleFunc("POST /api/v1/evidence/verify", s.authorize(s.verifyEvidence))
	mux.HandleFunc("POST /api/v1/hardening/enforce", s.authorize(s.enforce))
	mux.HandleFunc("GET /api/v1/hardening/components", s.authorize(s.hardeningComponents))
	mux.HandleFunc("POST /api/v1/hardening/components", s.authorize(s.enforceHardeningComponent))
	mux.HandleFunc("POST /api/v1/hardening/rollback", s.authorize(s.rollback))
	mux.HandleFunc("POST /api/v1/audit/run", s.authorize(s.runAudit))
	mux.HandleFunc("GET /api/v1/xdr/findings", s.authorize(s.xdrFindings))
	mux.HandleFunc("POST /api/v1/xdr/scan", s.authorize(s.runXDR))
	mux.HandleFunc("GET /api/v1/mhx/status", s.authorize(s.mhxStatus))
	mux.HandleFunc("GET /api/v1/mhx/analyses", s.authorize(s.mhxAnalyses))
	mux.HandleFunc("POST /api/v1/mhx/feeds/sync", s.authorize(s.mhxSyncFeeds))
	mux.HandleFunc("POST /api/v1/mhx/mode", s.authorize(s.mhxSetMode))
	mux.HandleFunc("GET /api/v1/mhx/applications", s.authorize(s.mhxApplications))
	mux.HandleFunc("POST /api/v1/mhx/applications", s.authorize(s.mhxSetApplication))
	mux.HandleFunc("GET /api/v1/integrity/status", s.authorize(s.integrityStatus))
	mux.HandleFunc("GET /api/v1/integrity/changes", s.authorize(s.integrityChanges))
	mux.HandleFunc("POST /api/v1/integrity/configuration", s.authorize(s.integrityConfiguration))
	mux.HandleFunc("POST /api/v1/integrity/scan", s.authorize(s.integrityScan))
	return s.headers(mux)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	raw, err := assets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(raw)
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || (host != "127.0.0.1" && host != "localhost") {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.allowRequest(r.RemoteAddr) {
			w.Header().Set("Retry-After", "10")
			s.writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowRequest(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	window := s.rates[host]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = rateWindow{started: now}
	}
	if window.count >= 240 {
		return false
	}
	window.count++
	s.rates[host] = window
	return true
}

func (s *Server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			s.writeError(w, http.StatusForbidden, "request rejected")
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !security.TokenEqual(provided, s.token) && !s.sessionValid(r) {
			s.writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		if r.Method != http.MethodGet && !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		next(w, r)
	}
}

func (s *Server) masterAuthorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) || !security.TokenEqual(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), s.token) || !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		next(w, r)
	}
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "http://"+r.Host
}

func randomCredential() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Server) bootstrap(w http.ResponseWriter, _ *http.Request) {
	code, err := randomCredential()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session initialization failed")
		return
	}
	s.sessionMu.Lock()
	s.purgeSessionsLocked(time.Now())
	s.bootstrapCodes[code] = time.Now().Add(time.Minute)
	s.sessionMu.Unlock()
	s.writeJSON(w, http.StatusCreated, map[string]string{"code": code})
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	now := time.Now()
	s.sessionMu.Lock()
	expires, exists := s.bootstrapCodes[input.Code]
	delete(s.bootstrapCodes, input.Code)
	s.purgeSessionsLocked(now)
	s.sessionMu.Unlock()
	if !exists || now.After(expires) {
		s.writeError(w, http.StatusUnauthorized, "bootstrap code rejected")
		return
	}
	session, err := randomCredential()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session initialization failed")
		return
	}
	s.sessionMu.Lock()
	s.sessions[session] = now.Add(8 * time.Hour)
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "VGTSESSION", Value: session, Path: "/", MaxAge: 8 * 60 * 60, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (s *Server) sessionValid(r *http.Request) bool {
	cookie, err := r.Cookie("VGTSESSION")
	if err != nil || cookie.Value == "" {
		return false
	}
	now := time.Now()
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.purgeSessionsLocked(now)
	expires, exists := s.sessions[cookie.Value]
	return exists && now.Before(expires)
}

func (s *Server) purgeSessionsLocked(now time.Time) {
	for code, expiry := range s.bootstrapCodes {
		if now.After(expiry) {
			delete(s.bootstrapCodes, code)
		}
	}
	for session, expiry := range s.sessions {
		if now.After(expiry) {
			delete(s.sessions, session)
		}
	}
}

func (s *Server) claim(id string) bool {
	if len(id) < 32 || len(id) > 64 {
		return false
	}
	for _, char := range id {
		if !((char >= 'a' && char <= 'f') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}
	now := time.Now()
	s.replay.mu.Lock()
	defer s.replay.mu.Unlock()
	for key, expiry := range s.replay.items {
		if now.After(expiry) {
			delete(s.replay.items, key)
		}
	}
	if _, exists := s.replay.items[id]; exists {
		return false
	}
	s.replay.items[id] = now.Add(10 * time.Minute)
	return true
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	result, err := s.engine.Audit(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "security telemetry unavailable")
		return
	}
	platform := result.WindowsProductName
	if platform == "" {
		platform = "Windows 11 LTSC"
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"version": s.version, "platform": platform, "mode": "enterprise-balanced", "protection": result, "mhx": s.mhx.Status(), "integrity": s.integrity.Status()})
}

func (s *Server) enforce(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	result, err := s.engine.Enforce(r.Context(), input.Profile)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "hardening operation failed")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.Rollback(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "rollback failed")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) hardeningComponents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	components, err := s.engine.Components(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "hardening status unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, components)
}

func (s *Server) enforceHardeningComponent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(w, r, &input); err != nil || len(input.ID) < 2 || len(input.ID) > 64 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	components, err := s.engine.EnforceComponent(ctx, input.ID)
	if err != nil {
		s.writeError(w, http.StatusConflict, "hardening component rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, components)
}

func (s *Server) runAudit(w http.ResponseWriter, r *http.Request) {
	result, err := s.audit.Run(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "security audit failed")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) xdrFindings(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.xdr.Last())
}

func (s *Server) runXDR(w http.ResponseWriter, r *http.Request) {
	result, err := s.xdr.Scan(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "XDR scan failed")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) mhxStatus(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.mhx.Status())
}

func (s *Server) mhxAnalyses(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.mhx.Analyses(100))
}

func (s *Server) mhxSyncFeeds(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.mhx.SyncFeeds(ctx); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "threat intelligence synchronization failed")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.Status().ThreatIntelligence)
}

func (s *Server) mhxSetMode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Mode         string `json:"mode"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if input.Mode == "sovereign" && input.Confirmation != "SOVEREIGN DEFAULT DENY" {
		s.writeError(w, http.StatusConflict, "explicit sovereign-mode confirmation required")
		return
	}
	if err := s.mhx.SetMode(input.Mode); err != nil {
		s.writeError(w, http.StatusBadRequest, "protection mode rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.Status())
}

func (s *Server) mhxApplications(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.mhx.Applications(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "application allow policy unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) mhxSetApplication(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Action string `json:"action"`
		Path   string `json:"path"`
	}
	if err := decodeJSON(w, r, &input); err != nil || (input.Action != "Add" && input.Action != "Remove") || len(input.Path) < 3 || len(input.Path) > 1024 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.mhx.SetApplication(ctx, input.Action, input.Path)
	if err != nil {
		s.writeError(w, http.StatusConflict, "application allow transaction rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) integrityStatus(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.integrity.Status())
}

func (s *Server) integrityChanges(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 500, 1, 5000)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid change window")
		return
	}
	offset, err := parseBoundedInteger(r.URL.Query().Get("offset"), 0, 0, 10_000_000)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid change window")
		return
	}
	changes, err := s.integrity.Changes(limit, offset)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "integrity report unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, changes)
}

func (s *Server) integrityConfiguration(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled       bool `json:"enabled"`
		IntervalHours int  `json:"intervalHours"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	status, err := s.integrity.Configure(input.Enabled, input.IntervalHours)
	if err != nil {
		s.writeError(w, http.StatusConflict, "integrity configuration rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, status)
}

func (s *Server) integrityScan(w http.ResponseWriter, _ *http.Request) {
	if err := s.integrity.Start(); err != nil {
		s.writeError(w, http.StatusConflict, "integrity scan rejected")
		return
	}
	s.writeJSON(w, http.StatusAccepted, s.integrity.Status())
}

func parseBoundedInteger(value string, fallback, minimum, maximum int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, errors.New("integer boundary rejected")
	}
	return parsed, nil
}

func (s *Server) evidence(w http.ResponseWriter, _ *http.Request) {
	records, err := s.ledger.Snapshot(100)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "evidence unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, records)
}

func (s *Server) verifyEvidence(w http.ResponseWriter, _ *http.Request) {
	if err := s.ledger.Verify(); err != nil {
		s.writeError(w, http.StatusConflict, "evidence verification failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("JSON body required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data rejected")
	}
	return nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(payload)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}
