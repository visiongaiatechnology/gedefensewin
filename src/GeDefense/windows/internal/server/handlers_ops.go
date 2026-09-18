// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) enforce(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.engine.Enforce(ctx, strings.TrimSpace(input.Profile))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "hardening operation failed")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.engine.Rollback(ctx)
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	result, err := s.audit.Run(ctx)
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
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.xdr.Scan(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "XDR scan failed")
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
		return 0, strconv.ErrSyntax
	}
	return parsed, nil
}
