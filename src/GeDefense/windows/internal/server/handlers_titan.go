// STATUS: DIAMANT VGT SUPREME
package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/titan"
)

type titanReasonRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) titanAvailable(w http.ResponseWriter) bool {
	if s.titan == nil {
		s.writeError(w, http.StatusServiceUnavailable, "titan is not available in this build")
		return false
	}
	return true
}

func (s *Server) titanStatus(w http.ResponseWriter, _ *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	s.writeJSON(w, http.StatusOK, s.titan.Status())
}

func (s *Server) titanEvents(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	limit, err := parseTitanWindow(r.URL.Query().Get("limit"), 50, 1, 100)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	offset, err := parseTitanWindow(r.URL.Query().Get("offset"), 0, 0, 1_000_000)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	filter := titan.EventFilter(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter"))))
	if filter == "" {
		filter = titan.FilterAll
	}
	if !titan.ValidFilter(filter) {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	events, total, err := s.titan.Events(limit, offset, filter)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total, "limit": limit, "offset": offset, "filter": filter})
}

func (s *Server) titanQuarantine(w http.ResponseWriter, _ *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	entries := s.titan.QuarantineEntries()
	var bytes int64
	for _, entry := range entries {
		bytes += entry.Size
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": len(entries), "bytes": bytes})
}

func (s *Server) titanQuarantineEvent(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input titanReasonRequest
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	entry, err := s.titan.QuarantineEvent(r.PathValue("id"), input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan action rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"entry": entry})
}

func (s *Server) titanAcknowledgeEvent(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input titanReasonRequest
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.titan.AcknowledgeEvent(r.PathValue("id"), input.Reason); err != nil {
		s.writeError(w, http.StatusConflict, "titan action rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) titanAcknowledgeOpenFindings(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input struct {
		Limit  int    `json:"limit"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil ||
		input.Limit < 1 || input.Limit > 100 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	reviewed, err := s.titan.AcknowledgeOpenFindings(input.Limit, input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan review rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"reviewed": reviewed})
}

func (s *Server) titanRestore(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input titanReasonRequest
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	entry, err := s.titan.RestoreQuarantine(r.PathValue("id"), input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan action rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"entry": entry})
}

func (s *Server) titanReview(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input titanReasonRequest
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	entry, err := s.titan.ReviewQuarantine(r.PathValue("id"), input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan action rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"entry": entry})
}

func (s *Server) titanPolicy(w http.ResponseWriter, _ *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	s.writeJSON(w, http.StatusOK, s.titan.Policy())
}

func (s *Server) titanSetPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input struct {
		Mode           string `json:"mode"`
		AutoQuarantine bool   `json:"autoQuarantine"`
		Reason         string `json:"reason"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	policy, err := s.titan.SetPolicy(input.Mode, input.AutoQuarantine, input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan policy rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, policy)
}

func (s *Server) titanPermits(w http.ResponseWriter, _ *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"permits": s.titan.Permits()})
}

func (s *Server) titanCreatePermit(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input struct {
		Path         string `json:"path"`
		SHA256       string `json:"sha256"`
		Action       string `json:"action"`
		TTLMinutes   int    `json:"ttlMinutes"`
		SingleUse    bool   `json:"singleUse"`
		Reason       string `json:"reason"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil ||
		input.Confirmation != "CREATE TITAN PERMIT" || input.TTLMinutes < 5 || input.TTLMinutes > 43200 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	permit, err := s.titan.CreatePermit(input.Path, input.SHA256, input.Action,
		time.Duration(input.TTLMinutes)*time.Minute, input.SingleUse, input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan permit rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"permit": permit})
}

func (s *Server) titanRevokePermit(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input titanReasonRequest
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	policy, err := s.titan.RevokePermit(r.PathValue("id"), input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan permit rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, policy)
}

func (s *Server) titanSetOwnerProcessImages(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input struct {
		Images       []string `json:"images"`
		Reason       string   `json:"reason"`
		Confirmation string   `json:"confirmation"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	policy, err := s.titan.SetOwnerProcessImages(input.Images, input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan owner process images rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, policy)
}

func (s *Server) titanAddDevelopmentRoot(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input struct {
		Path         string `json:"path"`
		Reason       string `json:"reason"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	policy, err := s.titan.AddDevelopmentRoot(input.Path, input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan development root rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, policy)
}

func (s *Server) titanRemoveDevelopmentRoot(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	var input struct {
		Path         string `json:"path"`
		Reason       string `json:"reason"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	policy, err := s.titan.RemoveDevelopmentRoot(input.Path, input.Reason)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan development root rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, policy)
}

func (s *Server) titanCheckpoints(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	limit, err := parseTitanWindow(r.URL.Query().Get("limit"), 50, 1, 100)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"checkpoints": s.titan.Checkpoints(limit)})
}

func (s *Server) titanVerify(w http.ResponseWriter, _ *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	s.writeJSON(w, http.StatusOK, s.titan.Verify())
}

func (s *Server) titanExport(w http.ResponseWriter, r *http.Request) {
	if !s.titanAvailable(w) {
		return
	}
	limit, err := parseTitanWindow(r.URL.Query().Get("limit"), 200, 1, 500)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	bundle, err := s.titan.Export(limit)
	if err != nil {
		s.writeError(w, http.StatusConflict, "titan evidence export rejected")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="gedefense-titan-evidence.json"`)
	s.writeJSON(w, http.StatusOK, bundle)
}

func parseTitanWindow(raw string, fallback, minimum, maximum int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, errInvalidTitanWindow
	}
	return value, nil
}

var errInvalidTitanWindow = errors.New("titan window is invalid")
