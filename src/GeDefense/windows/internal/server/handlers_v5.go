// STATUS: PLATIN
package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

type mhxPolicySettingsProvider interface {
	PolicySettings() mhx.PolicySettings
	SetPolicySettings(context.Context, mhx.PolicySettingsPatch) (mhx.PolicySettings, error)
}

// mhxFeedPolicyProvider is the V5 per-feed threat-intelligence authority
// contract. It is a narrow optional interface so existing MHXEngine test
// doubles keep compiling.
type mhxFeedPolicyProvider interface {
	FeedPolicy() mhx.FeedPolicySnapshot
	SetFeedActions(context.Context, []mhx.FeedActionUpdate, string) (mhx.FeedPolicySnapshot, error)
}
type mhxKineticSettingsProvider interface {
	KineticSettings() mhx.KineticSettingsSnapshot
	SetKineticConfig(context.Context, kinetic.Config) (mhx.KineticSettingsSnapshot, error)
	SetKineticDesiredState(context.Context, bool) (mhx.KineticSettingsSnapshot, error)
}
type mhxThreatIntelPollingProvider interface {
	ThreatIntelPolling() threatintel.PollingConfig
	SetThreatIntelPolling(context.Context, int) (threatintel.PollingConfig, error)
}
type mhxNotificationProvider interface {
	Notifications(int) []mhx.Notification
}

type mhxApplicationDenyProvider interface {
	ApplicationDenies(context.Context) ([]mhx.ApplicationDeny, error)
	SetApplicationDeny(context.Context, string, string) ([]mhx.ApplicationDeny, error)
}

func (s *Server) mhxSettings(w http.ResponseWriter, _ *http.Request) {
	provider, ok := s.mhx.(mhxPolicySettingsProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "XDR settings are not available in this build")
		return
	}
	policy := provider.PolicySettings()
	status := s.mhx.Status()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": policy.SchemaVersion,
		"aggressiveness": map[string]string{
			"process": policy.Aggressiveness, "network": policy.Aggressiveness, "application": policy.Aggressiveness,
		},
		"autoResponse": map[string]any{
			"terminate": policy.AutoResponse.TerminateProcess, "correlatedNetworkResponse": policy.AutoResponse.CorrelatedNetworkResponse,
			"minimumSeverity": policy.AutoResponse.MinimumSeverity,
		},
		"notifications": map[string]any{
			"events": policy.Notifications.EventFeedEnabled, "blockEvents": policy.Notifications.BlockEvents,
			"critical": policy.Notifications.MinimumSeverity, "windowsToasts": policy.Notifications.WindowsToasts,
			"toastMinimumSeverity": policy.Notifications.ToastMinimumSeverity,
		},
		"applicationNetworkRestrictions": map[string]any{
			"unknownPolicy": "audit", "appControlMode": status.ProtectionMode,
			"allowListEnforced": policy.Application.AllowListEnforced, "denyListSupported": policy.Application.DenyListSupported,
		},
		"autoDisarmMinutes": 0,
		"source":            policy.Source, "warnings": policy.Warnings,
		"readOnly": map[string]any{
			"network": policy.Network, "application": policy.Application, "process": policy.Process,
		},
	})
}

func (s *Server) mhxSetSettings(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxPolicySettingsProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "XDR settings are not available in this build")
		return
	}
	var input struct {
		Aggressiveness struct {
			Process     string `json:"process"`
			Network     string `json:"network"`
			Application string `json:"application"`
		} `json:"aggressiveness"`
		AutoResponse struct {
			Terminate *bool `json:"terminate"`
		} `json:"autoResponse"`
		Notifications struct {
			Events               *bool  `json:"events"`
			Critical             *bool  `json:"critical"`
			WindowsToasts        *bool  `json:"windowsToasts"`
			ToastMinimumSeverity string `json:"toastMinimumSeverity"`
		} `json:"notifications"`
		ApplicationNetworkRestrictions struct {
			UnknownPolicy  string `json:"unknownPolicy"`
			AppControlMode string `json:"appControlMode"`
		} `json:"applicationNetworkRestrictions"`
		AutoDisarmMinutes float64 `json:"autoDisarmMinutes"`
		Reason            string  `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 32<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	current := provider.PolicySettings()
	patch := mhx.PolicySettingsPatch{}
	if levels := []string{input.Aggressiveness.Process, input.Aggressiveness.Network, input.Aggressiveness.Application}; levels[0] != "" || levels[1] != "" || levels[2] != "" {
		for _, level := range levels {
			if level != "" && level != levels[0] {
				s.writeError(w, http.StatusConflict, "per-domain aggressiveness is not independently enforceable; select one value for process, network and application")
				return
			}
		}
		level := strings.TrimSpace(levels[0])
		patch.Aggressiveness = &level
	}
	if input.AutoResponse.Terminate != nil {
		settings := current.AutoResponse
		settings.TerminateProcess = *input.AutoResponse.Terminate
		patch.AutoResponse = &settings
	}
	notificationSettings := current.Notifications
	notificationChanged := false
	if input.Notifications.Events != nil {
		notificationSettings.EventFeedEnabled = *input.Notifications.Events
		notificationChanged = true
	}
	if input.Notifications.Critical != nil {
		if *input.Notifications.Critical {
			notificationSettings.MinimumSeverity = mhx.SeverityCritical
		} else {
			notificationSettings.MinimumSeverity = mhx.SeverityLow
		}
		notificationChanged = true
	}
	if input.Notifications.WindowsToasts != nil {
		notificationSettings.WindowsToasts = *input.Notifications.WindowsToasts
		notificationChanged = true
	}
	if input.Notifications.ToastMinimumSeverity != "" {
		notificationSettings.ToastMinimumSeverity = mhx.Severity(strings.ToUpper(strings.TrimSpace(input.Notifications.ToastMinimumSeverity)))
		notificationChanged = true
	}
	if notificationChanged {
		patch.Notifications = &notificationSettings
	}
	if input.ApplicationNetworkRestrictions.UnknownPolicy != "" && input.ApplicationNetworkRestrictions.UnknownPolicy != "audit" {
		s.writeError(w, http.StatusConflict, "unknown-application policy is not independently enforceable in this build")
		return
	}
	if input.AutoDisarmMinutes != 0 {
		s.writeError(w, http.StatusConflict, "XDR auto-disarm is not supported; use the Kinetic policy for timed disarm")
		return
	}
	if patch.Aggressiveness == nil && patch.AutoResponse == nil && patch.Notifications == nil {
		s.writeError(w, http.StatusBadRequest, "no supported setting supplied")
		return
	}
	updated, err := provider.SetPolicySettings(r.Context(), patch)
	if err != nil {
		s.writeInternalError(w, http.StatusConflict, "XDR settings rejected", "xdr settings apply", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"settings": updated, "source": updated.Source})
}

func (s *Server) kineticSettings(w http.ResponseWriter, _ *http.Request) {
	provider, ok := s.mhx.(mhxKineticSettingsProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Kinetic settings are not available in this build")
		return
	}
	s.writeJSON(w, http.StatusOK, kineticSettingsPayload(provider.KineticSettings()))
}

func kineticSettingsPayload(snapshot mhx.KineticSettingsSnapshot) map[string]any {
	return map[string]any{
		"schemaVersion": snapshot.SchemaVersion, "armed": snapshot.Armed, "observe": snapshot.Observe,
		"desiredArmed": snapshot.DesiredArmed, "persisted": snapshot.Persisted, "armedAfterRestart": snapshot.DesiredArmed,
		"mode": snapshot.Mode, "source": snapshot.ConfigSource, "persistenceSource": snapshot.ArmingSource,
		"thresholds": map[string]any{
			"windowSeconds": snapshot.Config.BurstWindowSeconds, "minEvents": snapshot.Config.MinEvents,
			"minDistinctPorts": snapshot.Config.MinDistinctPorts, "autoDisarmSeconds": snapshot.Config.AutoDisarmSeconds,
		},
		"limits": snapshot.Limits, "requirements": snapshot.Requirements, "autoRearm": snapshot.AutoRearm,
		"reason": snapshot.Reason, "configWarning": snapshot.ConfigWarning,
		"rearmedAfterRestart": snapshot.Armed && snapshot.DesiredArmed,
	}
}

func (s *Server) kineticSetSettings(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxKineticSettingsProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Kinetic settings are not available in this build")
		return
	}
	var input struct {
		ArmedAfterRestart *bool `json:"armedAfterRestart"`
		Thresholds        struct {
			WindowSeconds    int   `json:"windowSeconds"`
			MinEvents        int   `json:"minEvents"`
			Ports            []int `json:"ports"`
			MinDistinctPorts *int  `json:"minDistinctPorts"`
		} `json:"thresholds"`
		AutoDisarmMinutes *float64 `json:"autoDisarmMinutes"`
		Notifications     struct {
			Enabled *bool `json:"enabled"`
		} `json:"notifications"`
		Reason string `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 32<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if len(input.Thresholds.Ports) > 0 && input.Thresholds.MinDistinctPorts != nil {
		s.writeError(w, http.StatusConflict, "use either minDistinctPorts or a ports list, not both")
		return
	}
	current := provider.KineticSettings()
	config := current.Config
	if input.Thresholds.WindowSeconds != 0 {
		config.BurstWindowSeconds = input.Thresholds.WindowSeconds
	}
	if input.Thresholds.MinEvents != 0 {
		config.MinEvents = input.Thresholds.MinEvents
	}
	if input.Thresholds.MinDistinctPorts != nil {
		config.MinDistinctPorts = *input.Thresholds.MinDistinctPorts
	}
	if len(input.Thresholds.Ports) > 0 {
		if len(input.Thresholds.Ports) > kinetic.MaxDistinctPorts {
			s.writeError(w, http.StatusConflict, "too many distinct ports")
			return
		}
		config.MinDistinctPorts = len(input.Thresholds.Ports)
	}
	if input.AutoDisarmMinutes != nil {
		if *input.AutoDisarmMinutes < 0 || *input.AutoDisarmMinutes > 7*24*60 || (float64(int(*input.AutoDisarmMinutes)) != *input.AutoDisarmMinutes) {
			s.writeError(w, http.StatusConflict, "invalid auto-disarm window")
			return
		}
		config.AutoDisarmSeconds = int(*input.AutoDisarmMinutes * 60)
	}
	if err := config.Validate(); err != nil {
		s.writeInternalError(w, http.StatusConflict, "Kinetic settings rejected", "kinetic settings validation", err)
		return
	}
	updated, err := provider.SetKineticConfig(r.Context(), config)
	if err != nil {
		s.writeError(w, http.StatusConflict, "Kinetic settings rejected")
		return
	}
	if input.ArmedAfterRestart != nil {
		desired, err := provider.SetKineticDesiredState(r.Context(), *input.ArmedAfterRestart)
		if err != nil {
			log.Printf("kinetic desired state rejected: %v", err)
			updated = provider.KineticSettings()
			s.writeJSON(w, http.StatusConflict, map[string]any{
				"settings": kineticSettingsPayload(updated),
				// Never forward raw engine text: the client only receives the class
				// plus an opaque error id for support correlation (AN-FIND-009).
				"error": "Kinetic desired state rejected", "errorId": s.newErrorID(),
			})
			return
		}
		updated = desired
	}
	if input.Notifications.Enabled != nil {
		if provider, ok := s.mhx.(mhxPolicySettingsProvider); ok {
			current := provider.PolicySettings()
			notifications := current.Notifications
			notifications.KineticEvents = *input.Notifications.Enabled
			if _, err := provider.SetPolicySettings(r.Context(), mhx.PolicySettingsPatch{Notifications: &notifications}); err != nil {
				s.writeError(w, http.StatusConflict, "Kinetic notification settings rejected")
				return
			}
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"settings": kineticSettingsPayload(updated), "source": updated.ConfigSource})
}

func (s *Server) threatIntelStatus(w http.ResponseWriter, _ *http.Request) {
	status := s.mhx.Status()
	ti := status.ThreatIntelligence
	polling := status.ThreatIntelPolling
	s.writeJSON(w, http.StatusOK, map[string]any{
		"state": ti.State, "indicators": ti.Indicators, "blockingIndicators": ti.BlockingIndicators,
		"blockingFeedsReady": ti.BlockingFeedsReady, "blockingFeedsTotal": ti.BlockingFeedsTotal,
		"lastAttemptUtc": ti.LastAttemptUTC, "lastSuccessUtc": ti.LastSuccessUTC, "nextSyncUtc": ti.NextSyncUTC,
		"pollIntervalMinutes": polling.IntervalSeconds / 60, "intervalSeconds": polling.IntervalSeconds,
		"pollingSource": polling.Source, "pollingUpdatedUtc": polling.UpdatedUTC,
		"lastPollAttemptUtc": polling.LastAttemptUTC, "lastPollSuccessUtc": polling.LastSyncUTC, "nextPollUtc": polling.NextPollUTC,
		"minIntervalSeconds": polling.MinIntervalSeconds, "maxIntervalSeconds": polling.MaxIntervalSeconds,
		"error": ti.Error, "pollingError": polling.Error, "feeds": ti.Feeds,
		"feedPolicySource": ti.FeedPolicySource, "feedPolicyUpdatedUtc": ti.FeedPolicyUpdatedUTC,
		"feedPolicyOverrides": ti.FeedPolicyOverrides, "feedPolicyError": ti.FeedPolicyError,
		"threatEnforcement": status.ThreatEnforcement,
	})
}

func (s *Server) threatIntelSetSettings(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxThreatIntelPollingProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Threat Intelligence polling settings are not available in this build")
		return
	}
	var input struct {
		PollIntervalMinutes int    `json:"pollIntervalMinutes"`
		Reason              string `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 16<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if input.PollIntervalMinutes < 5 || input.PollIntervalMinutes > 1440 {
		s.writeError(w, http.StatusConflict, "polling interval must be between 5 and 1440 minutes")
		return
	}
	polling, err := provider.SetThreatIntelPolling(r.Context(), input.PollIntervalMinutes*60)
	if err != nil {
		s.writeError(w, http.StatusConflict, "Threat Intelligence polling configuration rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"pollIntervalMinutes": polling.IntervalSeconds / 60, "intervalSeconds": polling.IntervalSeconds,
		"source": polling.Source, "updatedUtc": polling.UpdatedUTC, "nextPollUtc": polling.NextPollUTC,
	})
}

func (s *Server) mhxApplicationDenies(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxApplicationDenyProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "application network-deny rules are not available in this build")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	entries, err := provider.ApplicationDenies(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "application network-deny inventory unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, entries)
}

func (s *Server) mhxSetApplicationDeny(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxApplicationDenyProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "application network-deny rules are not available in this build")
		return
	}
	var input struct {
		Action string `json:"action"`
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 16<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	entries, err := provider.SetApplicationDeny(ctx, input.Action, input.Path)
	if err != nil {
		s.writeInternalError(w, http.StatusConflict, "application network-deny transaction rejected", "application deny transaction", err)
		return
	}
	s.writeJSON(w, http.StatusOK, entries)
}

func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 50, 1, 100)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid notification window")
		return
	}
	result := make([]mhx.Notification, 0, limit)
	if provider, ok := s.mhx.(mhxNotificationProvider); ok {
		result = append(result, provider.Notifications(limit)...)
	}
	if s.titan != nil {
		for _, notification := range s.titan.Notifications(limit) {
			result = append(result, mhx.Notification{
				ID: notification.ID, TimestampUTC: notification.TimestampUTC, Kind: notification.Kind,
				Severity: mhx.Severity(notification.Severity), Title: notification.Title, Detail: notification.Detail,
			})
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].TimestampUTC.After(result[right].TimestampUTC)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	s.writeJSON(w, http.StatusOK, result)
}

// mhxFeedPolicy serves GET /api/v1/mhx/threat-intelligence/feed-policy.
func (s *Server) mhxFeedPolicy(w http.ResponseWriter, _ *http.Request) {
	provider, ok := s.mhx.(mhxFeedPolicyProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "threat feed authority is not available in this build")
		return
	}
	s.writeJSON(w, http.StatusOK, provider.FeedPolicy())
}

// mhxSetFeedPolicy serves POST /api/v1/mhx/threat-intelligence/feed-policy.
//
// The response is the post-change policy snapshot. `pending=true` and
// per-feed `enforcement=PENDING_WFP_VERIFICATION` mean the requested blocking
// authority is persisted but not yet matched by a verified WFP generation; a
// mutation is never reported as verified blocking before the engine verified
// the active generation.
func (s *Server) mhxSetFeedPolicy(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxFeedPolicyProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "threat feed authority is not available in this build")
		return
	}
	var input struct {
		Feeds []struct {
			FeedID string `json:"feedId"`
			Action string `json:"action"`
		} `json:"feeds"`
		Reason       string `json:"reason"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSONBounded(w, r, &input, 32<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if input.Confirmation != "UPDATE THREAT FEED POLICY" || validateReason(input.Reason) != nil || len(input.Feeds) == 0 || len(input.Feeds) > 16 {
		s.writeError(w, http.StatusBadRequest, "explicit feed policy confirmation and reason required")
		return
	}
	updates := make([]mhx.FeedActionUpdate, 0, len(input.Feeds))
	for _, feed := range input.Feeds {
		feedID := strings.TrimSpace(feed.FeedID)
		action := strings.TrimSpace(feed.Action)
		if len(feedID) == 0 || len(feedID) > 32 || len(action) == 0 || len(action) > 24 {
			s.writeError(w, http.StatusBadRequest, "invalid feed policy entry")
			return
		}
		updates = append(updates, mhx.FeedActionUpdate{FeedID: feedID, Action: action})
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Minute)
	defer cancel()
	snapshot, err := provider.SetFeedActions(ctx, updates, input.Reason)
	if err != nil {
		switch {
		case errors.Is(err, threatintel.ErrSyncInProgress):
			s.writeError(w, http.StatusConflict, "threat intelligence synchronization in progress; retry the feed policy update")
		case errors.Is(err, context.DeadlineExceeded):
			s.writeError(w, http.StatusServiceUnavailable, "feed policy verification timed out; policy intent remains pending")
		default:
			s.writeError(w, http.StatusConflict, "feed policy rejected: "+boundedFeedPolicyMessage(err))
		}
		return
	}
	s.writeJSON(w, http.StatusOK, snapshot)
}

// boundedFeedPolicyMessage keeps rejection detail explicit but bounded. The
// engine only returns controlled validation strings (feed IDs and actions),
// never secrets or paths.
func boundedFeedPolicyMessage(err error) string {
	if err == nil {
		return "rejected"
	}
	message := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, err.Error())
	runes := []rune(message)
	if len(runes) > 200 {
		runes = runes[:200]
	}
	if !utf8.ValidString(string(runes)) {
		return "rejected"
	}
	return string(runes)
}
