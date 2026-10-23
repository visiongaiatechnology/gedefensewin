// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/settings"
)

// SettingsService is the contract of the V5 settings authority consumed by the
// HTTP handlers. The Lead-owned constructor wires a *settings.Service (or a
// test double) into Server through SetSettingsService.
type SettingsService interface {
	Snapshot() settings.Snapshot
	Apply(context.Context, string, map[string]any, string, string) (settings.Result, error)
	Profiles() []settings.Profile
	CreateProfile(context.Context, settings.ProfileInput) (settings.Snapshot, error)
	UpdateProfile(context.Context, string, settings.ProfileInput) (settings.Snapshot, error)
	DeleteProfile(context.Context, string) (settings.Snapshot, error)
	ApplyProfile(context.Context, string, string, string) (settings.Snapshot, error)
}

// SetSettingsService attaches the settings authority. The Lead-owned
// NewWithStartup constructor calls this once during composition.
func (s *Server) SetSettingsService(service SettingsService) {
	s.settings = service
}

// settingsSnapshot serves GET /api/v1/settings.
func (s *Server) settingsSnapshot(w http.ResponseWriter, _ *http.Request) {
	if s.settings == nil {
		s.writeError(w, http.StatusServiceUnavailable, "settings service unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, s.settings.Snapshot())
}

type settingsApplyRequest struct {
	Section      string         `json:"section"`
	Values       map[string]any `json:"values"`
	Reason       string         `json:"reason"`
	Confirmation string         `json:"confirmation"`
}

// settingsApply serves POST /api/v1/settings. Authentication, loopback, origin,
// replay and rate limiting are enforced by the router wrapper (s.authorize).
func (s *Server) settingsApply(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		s.writeError(w, http.StatusServiceUnavailable, "settings service unavailable")
		return
	}
	var input settingsApplyRequest
	if err := decodeJSONBounded(w, r, &input, 64<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	input.Section = strings.TrimSpace(input.Section)
	if input.Section == "" || len(input.Section) > 64 || len(input.Values) == 0 || len(input.Values) > 128 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := validateReason(input.Reason); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(input.Confirmation) != settings.ConfirmationApplySettings {
		s.writeError(w, http.StatusConflict, "explicit settings confirmation required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	result, err := s.settings.Apply(ctx, input.Section, input.Values, strings.TrimSpace(input.Reason), input.Confirmation)
	if err != nil {
		s.writeSettingsError(w, err, "apply")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

type settingsProfilesResponse struct {
	Profiles        []settings.Profile `json:"profiles"`
	Levels          []settings.Level   `json:"levels"`
	ActiveProfileID string             `json:"activeProfileId"`
	ActiveLevel     string             `json:"activeLevel"`
	ProtectionLevel string             `json:"protectionLevel"`
	State           string             `json:"state"`
	ApplierReady    bool               `json:"applierReady"`
}

// settingsProfiles serves GET /api/v1/settings/profiles.
func (s *Server) settingsProfiles(w http.ResponseWriter, _ *http.Request) {
	if s.settings == nil {
		s.writeError(w, http.StatusServiceUnavailable, "settings service unavailable")
		return
	}
	snapshot := s.settings.Snapshot()
	s.writeJSON(w, http.StatusOK, settingsProfilesResponse{
		Profiles:        snapshot.Profiles,
		Levels:          snapshot.Levels,
		ActiveProfileID: snapshot.ActiveProfileID,
		ActiveLevel:     snapshot.ActiveLevel,
		ProtectionLevel: snapshot.ProtectionLevel,
		State:           snapshot.State,
		ApplierReady:    snapshot.ApplierReady,
	})
}

type settingsProfileRequest struct {
	Action       string                 `json:"action"`
	ID           string                 `json:"id,omitempty"`
	Profile      *settings.ProfileInput `json:"profile,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
	Confirmation string                 `json:"confirmation,omitempty"`
}

// settingsProfileMutation serves POST /api/v1/settings/profiles with the
// bounded actions list/create/update/delete/apply.
func (s *Server) settingsProfileMutation(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		s.writeError(w, http.StatusServiceUnavailable, "settings service unavailable")
		return
	}
	var input settingsProfileRequest
	if err := decodeJSONBounded(w, r, &input, 64<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	identifier := strings.TrimSpace(input.ID)
	switch action {
	case "list":
		s.settingsProfiles(w, r)
		return
	case "create":
		if input.Profile == nil {
			s.writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		snapshot, err := s.settings.CreateProfile(ctx, *input.Profile)
		if err != nil {
			s.writeSettingsError(w, err, "create-profile")
			return
		}
		s.writeJSON(w, http.StatusOK, snapshot)
	case "update":
		if input.Profile == nil || len(identifier) < 3 || len(identifier) > 32 {
			s.writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		input.Profile.ID = identifier
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		snapshot, err := s.settings.UpdateProfile(ctx, identifier, *input.Profile)
		if err != nil {
			s.writeSettingsError(w, err, "update-profile")
			return
		}
		s.writeJSON(w, http.StatusOK, snapshot)
	case "delete":
		if len(identifier) < 3 || len(identifier) > 32 {
			s.writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		snapshot, err := s.settings.DeleteProfile(ctx, identifier)
		if err != nil {
			s.writeSettingsError(w, err, "delete-profile")
			return
		}
		s.writeJSON(w, http.StatusOK, snapshot)
	case "apply":
		if len(identifier) < 3 || len(identifier) > 32 || validateReason(input.Reason) != nil || strings.TrimSpace(input.Confirmation) == "" {
			s.writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		snapshot, err := s.settings.ApplyProfile(ctx, identifier, strings.TrimSpace(input.Reason), strings.TrimSpace(input.Confirmation))
		if err != nil {
			s.writeSettingsError(w, err, "apply-profile")
			return
		}
		s.writeJSON(w, http.StatusOK, snapshot)
	default:
		s.writeError(w, http.StatusBadRequest, "invalid request")
	}
}

// writeSettingsError maps settings errors to opaque HTTP responses. Validation
// and conflict detail stays in the service/applier logs; clients only learn the
// error class and an opaque error id.
func (s *Server) writeSettingsError(w http.ResponseWriter, err error, operation string) {
	switch {
	case errors.Is(err, settings.ErrValidation):
		s.writeError(w, http.StatusBadRequest, "invalid settings request")
	case errors.Is(err, settings.ErrConflict):
		s.writeError(w, http.StatusConflict, "settings change rejected by protection policy")
	case errors.Is(err, settings.ErrUnavailable):
		s.writeError(w, http.StatusServiceUnavailable, "settings service unavailable")
	case errors.Is(err, settings.ErrPersistence):
		log.Printf("settings %s persistence failure: %v", operation, err)
		s.writeError(w, http.StatusInternalServerError, "settings persistence failed")
	default:
		log.Printf("settings %s failed: %v", operation, err)
		s.writeError(w, http.StatusInternalServerError, "settings operation failed")
	}
}
