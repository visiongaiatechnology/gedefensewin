// STATUS: DIAMANT VGT SUPREME
package server

import (
	"net/http"
	"time"
)

func (s *Server) bootstrap(w http.ResponseWriter, _ *http.Request) {
	code, err := randomCredential()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session initialization failed")
		return
	}
	now := time.Now()
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	if len(s.bootstrapCodes) >= maxBootstrapEntries {
		s.sessionMu.Unlock()
		s.writeError(w, http.StatusTooManyRequests, "session initialization rate limited")
		return
	}
	s.bootstrapCodes[code] = now.Add(time.Minute)
	s.sessionMu.Unlock()
	s.writeJSON(w, http.StatusCreated, map[string]string{"code": code})
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r, false) {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil || len(input.Code) != 43 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	now := time.Now()
	s.sessionMu.Lock()
	expires, exists := s.bootstrapCodes[input.Code]
	delete(s.bootstrapCodes, input.Code)
	s.purgeSessionsLocked(now)
	if !exists || now.After(expires) || len(s.sessions) >= maxSessionEntries {
		s.sessionMu.Unlock()
		s.writeError(w, http.StatusUnauthorized, "bootstrap code rejected")
		return
	}
	session, err := randomCredential()
	if err != nil {
		s.sessionMu.Unlock()
		s.writeError(w, http.StatusInternalServerError, "session initialization failed")
		return
	}
	s.sessions[session] = now.Add(8 * time.Hour)
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "VGTSESSION", Value: session, Path: "/", MaxAge: 8 * 60 * 60, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (s *Server) sessionValid(r *http.Request) bool {
	cookie, err := r.Cookie("VGTSESSION")
	if err != nil || len(cookie.Value) != 43 {
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
