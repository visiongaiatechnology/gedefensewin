package server

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type kineticArming interface {
	SetKineticArmed(context.Context, bool) error
}

func (s *Server) kineticSetMode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Mode         string `json:"mode"`
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(input.Mode))
	if (mode != "armed" && mode != "observe") || input.Confirmation != map[string]string{"armed": "ARM KINETIC TI", "observe": "DISARM KINETIC"}[mode] || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "explicit kinetic confirmation and reason required")
		return
	}
	controller, ok := s.mhx.(kineticArming)
	if !ok {
		s.writeError(w, http.StatusNotImplemented, "kinetic arming unavailable")
		return
	}
	if err := s.ledger.Append("kinetic.operator", "mode-change-request", mode); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "kinetic evidence unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := controller.SetKineticArmed(ctx, mode == "armed"); err != nil {
		s.writeError(w, http.StatusConflict, "kinetic readiness not satisfied")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"kinetic": s.mhx.Status().Kinetic, "armed": s.mhx.Status().KineticArmed})
}
