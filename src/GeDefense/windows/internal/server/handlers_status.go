// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type readiness struct {
	Target       string   `json:"target"`
	CurrentMode  string   `json:"currentMode"`
	Ready        bool     `json:"ready"`
	Blockers     []string `json:"blockers"`
	Consequences []string `json:"consequences"`
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	raw, err := assets.ReadFile("web/index.html")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "asset unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(raw)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	result, err := s.engine.Posture(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "security telemetry unavailable")
		return
	}
	platform := result.WindowsProductName
	if platform == "" {
		platform = "Windows"
	}
	mhxStatus := s.mhx.Status()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"version": s.version, "platform": platform, "mode": "adaptive-windows-defense",
		"protection": result, "mhx": mhxStatus, "integrity": s.integrity.Status(),
		"effectiveProtection": map[string]any{
			"mode":     mhxStatus.ProtectionMode,
			"active":   mhxStatus.ProtectionMode != "monitor" && mhxStatus.Realtime && mhxStatus.ProtectionHealth == "VERIFIED",
			"verified": mhxStatus.ProtectionHealth == "VERIFIED",
		},
	})
}

func (s *Server) protectionReadiness(w http.ResponseWriter, r *http.Request) {
	target := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("target")))
	if target != "monitor" && target != "guarded" && target != "sovereign" {
		s.writeError(w, http.StatusBadRequest, "invalid protection target")
		return
	}
	result := s.modeReady(target)
	if target == "guarded" {
		result.Consequences = append(result.Consequences, "Suspicious processes with a blocking MHX verdict may be terminated after identity revalidation")
	}
	if target == "sovereign" {
		result.Consequences = append(result.Consequences, "Windows App Control is enforced", "Outbound networking changes to default-deny policy")
	}
	s.writeJSON(w, http.StatusOK, result)
}
