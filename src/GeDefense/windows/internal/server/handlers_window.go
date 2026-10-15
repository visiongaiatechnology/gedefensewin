// STATUS: PLATIN
package server

import (
	"net/http"
	"time"
)

// The service never accesses the desktop. The launcher is the sole consumer.
func (s *Server) queueWindow(w http.ResponseWriter, action string) {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	if time.Since(s.windowClientAt) > 20*time.Second {
		s.writeError(w, http.StatusServiceUnavailable, "GeDefense window is not connected")
		return
	}
	select {
	case s.windowCommands <- action:
		s.writeJSON(w, http.StatusAccepted, map[string]any{"handled": true, "action": action})
	default:
		s.writeError(w, http.StatusTooManyRequests, "window command pending")
	}
}
func (s *Server) windowMinimize(w http.ResponseWriter, r *http.Request) { s.queueWindow(w, "minimize") }
func (s *Server) windowMaximize(w http.ResponseWriter, r *http.Request) { s.queueWindow(w, "maximize") }
func (s *Server) windowClose(w http.ResponseWriter, r *http.Request)    { s.queueWindow(w, "close") }
func (s *Server) windowDrag(w http.ResponseWriter, r *http.Request)     { s.queueWindow(w, "drag") }

func (s *Server) windowState(w http.ResponseWriter, r *http.Request) {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"state": s.windowStateVal, "handled": time.Since(s.windowClientAt) <= 20*time.Second,
	})
}
func (s *Server) windowPoll(w http.ResponseWriter, r *http.Request) {
	s.windowMu.Lock()
	s.windowClientAt = time.Now()
	s.windowMu.Unlock()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case cmd := <-s.windowCommands:
		s.writeJSON(w, http.StatusOK, map[string]string{"command": cmd})
	case <-timer.C:
		s.writeJSON(w, http.StatusOK, map[string]string{"command": "idle"})
	case <-r.Context().Done():
	}
}
func (s *Server) windowAck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State string `json:"state"`
	}
	if err := decodeJSON(w, r, &req); err != nil || (req.State != "normal" && req.State != "maximized" && req.State != "minimized" && req.State != "closed") {
		s.writeError(w, http.StatusBadRequest, "invalid window state")
		return
	}
	s.windowMu.Lock()
	s.windowStateVal = req.State
	s.windowClientAt = time.Now()
	if req.State == "closed" {
		s.windowClientAt = time.Time{}
		for len(s.windowCommands) > 0 {
			<-s.windowCommands
		}
	}
	s.windowMu.Unlock()
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
