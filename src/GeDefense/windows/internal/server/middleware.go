// STATUS: DIAMANT VGT SUPREME
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/security"
)

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.allowRequest(remoteHost) {
			w.Header().Set("Retry-After", "10")
			s.writeError(w, http.StatusTooManyRequests, "request rate limited")
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
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	for key, window := range s.rates {
		if now.Sub(window.started) >= 2*time.Minute {
			delete(s.rates, key)
		}
	}
	window := s.rates[remote]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = rateWindow{started: now}
	}
	if window.count >= 300 {
		return false
	}
	if _, exists := s.rates[remote]; !exists && len(s.rates) >= maxRateEntries {
		return false
	}
	window.count++
	s.rates[remote] = window
	return true
}

func (s *Server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		master := security.TokenEqual(provided, s.token)
		session := s.sessionValid(r)
		if !master && !session {
			s.writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		if !s.originAllowed(r, master) {
			s.writeError(w, http.StatusForbidden, "request rejected")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusConflict, "request rejected")
			return
		}
		next(w, r)
	}
}

func (s *Server) masterAuthorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !security.TokenEqual(provided, s.token) || !s.originAllowed(r, true) || !s.claim(r.Header.Get("X-VGT-Request-ID")) {
			s.writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		next(w, r)
	}
}

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
	for index, char := range id {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !((char >= 'a' && char <= 'f') || (char >= '0' && char <= '9')) {
			return false
		}
	}
	return true
}

func (s *Server) claim(id string) bool {
	if !validRequestID(id) {
		return false
	}
	now := time.Now()
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
