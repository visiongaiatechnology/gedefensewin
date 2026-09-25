// STATUS: DIAMANT VGT SUPREME
package server

import (
	"net/http"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func (s *Server) windowMinimize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	hwnd, err := winapi.FindGeDefenseWindow()
	if err != nil || hwnd == 0 {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"action":  "minimize",
			"handled": false,
			"mode":    "browser",
		})
		return
	}
	if err := winapi.MinimizeWindow(hwnd); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to minimize window")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"action":  "minimize",
		"handled": true,
		"mode":    "native",
	})
}

func (s *Server) windowMaximize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	hwnd, err := winapi.FindGeDefenseWindow()
	if err != nil || hwnd == 0 {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"action":    "maximize",
			"handled":   false,
			"mode":      "browser",
			"maximized": false,
		})
		return
	}
	maximized, err := winapi.MaximizeOrRestoreWindow(hwnd)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to toggle window maximize")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"action":    "maximize",
		"handled":   true,
		"mode":      "native",
		"maximized": maximized,
	})
}

func (s *Server) windowClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	hwnd, err := winapi.FindGeDefenseWindow()
	if err != nil || hwnd == 0 {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"action":  "close",
			"handled": false,
			"mode":    "browser",
		})
		return
	}
	if err := winapi.CloseWindow(hwnd); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to close window")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"action":  "close",
		"handled": true,
		"mode":    "native",
	})
}

func (s *Server) windowState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	hwnd, err := winapi.FindGeDefenseWindow()
	if err != nil || hwnd == 0 {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"state":   "normal",
			"handled": false,
			"mode":    "browser",
		})
		return
	}
	state, err := winapi.WindowState(hwnd)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to query window state")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"state":   state,
		"handled": true,
		"mode":    "native",
	})
}
