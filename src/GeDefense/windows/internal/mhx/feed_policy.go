// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

// Per-feed threat intelligence authority (Windows Beta V5)
//
// The MHX engine exposes the effective threat-feed policy as data and applies
// validated operator overrides through the threatintel manager. A BLOCK feed is
// only reported as effective after the corresponding WFP generation has been
// applied and verified; otherwise the response states pending/non-effective
// explicitly instead of silently claiming blocking.
const (
	maximumFeedPolicyUpdates     = 16
	minimumFeedPolicyReasonBytes = 8
	maximumFeedPolicyReasonBytes = 512
	feedPolicyDefaultSentinel    = "DEFAULT"
)

// FeedActionUpdate is one requested per-feed authority change. Action accepts
// BLOCK, CORRELATE_ONLY, ANNOTATE_ONLY or DEFAULT (reset to catalog authority).
type FeedActionUpdate struct {
	FeedID string `json:"feedId"`
	Action string `json:"action"`
}

// FeedPolicyLimits publishes the engine-side validation envelope.
type FeedPolicyLimits struct {
	MaxUpdates         int                  `json:"maxUpdates"`
	MaxOverrides       int                  `json:"maxOverrides"`
	MaximumFeedIDBytes int                  `json:"maximumFeedIdBytes"`
	MinimumReasonBytes int                  `json:"minimumReasonBytes"`
	MaximumReasonBytes int                  `json:"maximumReasonBytes"`
	AllowedActions     []threatintel.Action `json:"allowedActions"`
}

// FeedPolicyEntry is the honest per-feed state: the immutable catalog default,
// the operator-configured authority and whether the compiled/verified WFP
// generation currently reflects it.
type FeedPolicyEntry struct {
	FeedID            string             `json:"feedId"`
	Name              string             `json:"name"`
	DefaultAction     threatintel.Action `json:"defaultAction"`
	ConfiguredAction  threatintel.Action `json:"configuredAction"`
	EffectiveAction   threatintel.Action `json:"effectiveAction"`
	ActionSource      string             `json:"actionSource"`
	UpdatedUTC        time.Time          `json:"updatedUtc,omitempty"`
	Blocking          bool               `json:"blocking"`
	Indicators        int                `json:"indicators"`
	Ready             bool               `json:"ready"`
	FeedState         string             `json:"feedState"`
	EnforcementImpact string             `json:"enforcementImpact"`
	// Enforcement is VERIFIED_BLOCK, PENDING_WFP_VERIFICATION or NOT_BLOCKING.
	Enforcement string `json:"enforcement"`
}

// FeedPolicySnapshot is the API/UI contract for GET feed policy and the POST
// result. Pending is true while a requested blocking authority cannot yet be
// matched by a verified active WFP generation.
type FeedPolicySnapshot struct {
	SchemaVersion                 int               `json:"schemaVersion"`
	StoreState                    string            `json:"storeState"`
	StoreError                    string            `json:"storeError,omitempty"`
	PolicyUpdatedUTC              time.Time         `json:"updatedUtc,omitempty"`
	Generation                    string            `json:"generationSha256"`
	EnforcementGeneration         string            `json:"enforcementGenerationSha256"`
	PreviousEnforcementGeneration string            `json:"previousEnforcementGenerationSha256,omitempty"`
	EnforcementChanged            bool              `json:"enforcementChanged"`
	ActiveGeneration              string            `json:"activeEnforcementGenerationSha256,omitempty"`
	EnforcementState              string            `json:"enforcementState"`
	EnforcementError              string            `json:"enforcementError,omitempty"`
	WFPVerified                   bool              `json:"wfpVerified"`
	Pending                       bool              `json:"pending"`
	Warnings                      []string          `json:"warnings,omitempty"`
	Limits                        FeedPolicyLimits  `json:"limits"`
	Feeds                         []FeedPolicyEntry `json:"feeds"`
}

func defaultFeedPolicyLimits() FeedPolicyLimits {
	managerLimits := threatintel.FeedPolicyLimitsForAPI()
	return FeedPolicyLimits{
		MaxUpdates:         maximumFeedPolicyUpdates,
		MaxOverrides:       managerLimits.MaxOverrides,
		MaximumFeedIDBytes: managerLimits.MaximumFeedIDBytes,
		MinimumReasonBytes: minimumFeedPolicyReasonBytes,
		MaximumReasonBytes: maximumFeedPolicyReasonBytes,
		AllowedActions:     managerLimits.AllowedActions,
	}
}

// enforcementGenerationVerified reports whether the active WFP generation
// exactly matches the desired threat-intelligence generation.
func enforcementGenerationVerified(enforcement ThreatEnforcementStatus, desiredGeneration string, blockingIndicators int) bool {
	stateVerified := enforcement.State == "VERIFIED" || enforcement.State == "VERIFIED_CLEANUP_PENDING"
	return stateVerified && blockingIndicators > 0 && desiredGeneration != "" &&
		len(enforcement.ActiveGeneration) == 64 && enforcement.ActiveGeneration == desiredGeneration
}

// buildFeedPolicySnapshot projects the manager truth together with the verified
// WFP enforcement state. It never upgrades a pending BLOCK to verified.
func buildFeedPolicySnapshot(base threatintel.FeedPolicySnapshot, enforcement ThreatEnforcementStatus) FeedPolicySnapshot {
	limits := defaultFeedPolicyLimits()
	snapshot := FeedPolicySnapshot{
		SchemaVersion:         base.SchemaVersion,
		StoreState:            base.StoreState,
		StoreError:            base.StoreError,
		PolicyUpdatedUTC:      base.UpdatedUTC,
		Generation:            base.Generation,
		EnforcementGeneration: base.EnforcementGeneration,
		ActiveGeneration:      enforcement.ActiveGeneration,
		EnforcementState:      enforcement.State,
		EnforcementError:      enforcement.Error,
		Limits:                limits,
		Feeds:                 make([]FeedPolicyEntry, 0, len(base.Entries)),
	}
	snapshot.WFPVerified = enforcementGenerationVerified(enforcement, base.EnforcementGeneration, base.BlockingIndicators)
	snapshot.Pending = base.BlockingIndicators > 0 && !snapshot.WFPVerified
	for _, entry := range base.Entries {
		converted := FeedPolicyEntry{
			FeedID:            entry.FeedKey,
			Name:              entry.Name,
			DefaultAction:     entry.DefaultAction,
			ConfiguredAction:  entry.ConfiguredAction,
			EffectiveAction:   entry.EffectiveAction,
			ActionSource:      entry.Source,
			UpdatedUTC:        entry.UpdatedUTC,
			Blocking:          entry.Blocking,
			Indicators:        entry.Indicators,
			Ready:             entry.Ready,
			FeedState:         entry.FeedState,
			EnforcementImpact: entry.EnforcementImpact,
			Enforcement:       "NOT_BLOCKING",
		}
		if entry.Blocking {
			converted.Enforcement = "PENDING_WFP_VERIFICATION"
			if snapshot.WFPVerified {
				converted.Enforcement = "VERIFIED_BLOCK"
			}
		}
		snapshot.Feeds = append(snapshot.Feeds, converted)
	}
	if base.StoreState == "INVALID_DEFAULT" {
		snapshot.Warnings = append(snapshot.Warnings, "persisted feed policy is unreadable; catalog defaults are active and the invalid store was preserved for forensics")
	}
	if snapshot.Pending {
		warning := "blocking authority is not reported effective until the active WFP generation verifies"
		if enforcement.State != "" {
			warning += " (enforcement state " + truncate(enforcement.State, 64) + ")"
		}
		snapshot.Warnings = append(snapshot.Warnings, warning)
	}
	return snapshot
}

// FeedPolicy returns the current per-feed authority and WFP verification state.
func (e *Engine) FeedPolicy() FeedPolicySnapshot {
	if e == nil || e.feeds == nil {
		snapshot := FeedPolicySnapshot{SchemaVersion: threatintel.FeedPolicySchemaVersion, StoreState: "UNAVAILABLE", EnforcementState: "UNAVAILABLE", Limits: defaultFeedPolicyLimits(), Feeds: []FeedPolicyEntry{}}
		snapshot.Warnings = []string{"threat intelligence manager unavailable"}
		return snapshot
	}
	base := e.feeds.FeedPolicy()
	e.mu.RLock()
	enforcement := e.threatEnforcement
	e.mu.RUnlock()
	return buildFeedPolicySnapshot(base, enforcement)
}

// validateFeedPolicyReason returns the trimmed operator reason and its digest.
// Only the digest is persisted/ledgered; the free-text reason never reaches
// disk.
func validateFeedPolicyReason(reason string) (string, string, error) {
	trimmed := strings.TrimSpace(reason)
	if len(trimmed) < minimumFeedPolicyReasonBytes || len(trimmed) > maximumFeedPolicyReasonBytes {
		return "", "", fmt.Errorf("feed policy reason must be %d..%d bytes", minimumFeedPolicyReasonBytes, maximumFeedPolicyReasonBytes)
	}
	if !utf8.ValidString(trimmed) {
		return "", "", errors.New("feed policy reason is not valid UTF-8")
	}
	for _, character := range trimmed {
		if character < 0x20 || character == 0x7f {
			return "", "", errors.New("feed policy reason contains control characters")
		}
	}
	digest := sha256.Sum256([]byte(trimmed))
	return trimmed, hex.EncodeToString(digest[:]), nil
}

// normalizeFeedAction maps the API action string to a manager action. The
// DEFAULT sentinel resets the feed to its immutable catalog authority.
func normalizeFeedAction(value string) (*threatintel.Action, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	switch normalized {
	case feedPolicyDefaultSentinel:
		return nil, nil
	case string(threatintel.ActionBlock):
		action := threatintel.ActionBlock
		return &action, nil
	case string(threatintel.ActionCorrelateOnly):
		action := threatintel.ActionCorrelateOnly
		return &action, nil
	case string(threatintel.ActionAnnotateOnly):
		action := threatintel.ActionAnnotateOnly
		return &action, nil
	default:
		return nil, errors.New("unsupported feed authority action")
	}
}

func feedPolicyRequestSummary(updates []FeedActionUpdate) string {
	parts := make([]string, 0, len(updates))
	for _, update := range updates {
		parts = append(parts, strings.TrimSpace(update.FeedID)+"="+strings.ToUpper(strings.TrimSpace(update.Action)))
	}
	return truncate(strings.Join(parts, ","), 240)
}

// SetFeedActions validates, persists and applies per-feed authority overrides.
//
// Evidence: a request ledger entry (reason digest only) is written before any
// change; rejection, pending enforcement and verified enforcement are each
// recorded. Enforcement: when the resulting policy compiles blocking
// indicators, the WFP generation is applied synchronously and the response only
// reports VERIFIED_BLOCK after that verification. If application fails the
// override remains a persisted intent, the response reports pending and the
// intelligence loop retries the enforcement generation.
func (e *Engine) SetFeedActions(ctx context.Context, updates []FeedActionUpdate, reason string) (FeedPolicySnapshot, error) {
	if e == nil || e.feeds == nil {
		return FeedPolicySnapshot{}, errors.New("threat intelligence manager unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return e.FeedPolicy(), errors.New("feed policy update requires an active request")
	}
	if len(updates) == 0 || len(updates) > maximumFeedPolicyUpdates {
		return e.FeedPolicy(), fmt.Errorf("feed policy update count must be 1..%d", maximumFeedPolicyUpdates)
	}
	_, reasonDigest, err := validateFeedPolicyReason(reason)
	if err != nil {
		e.ledgerAppend("threat-intelligence.feed-policy", "request", "rejected")
		return e.FeedPolicy(), err
	}
	changes := make([]threatintel.FeedActionChange, 0, len(updates))
	seen := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		feedID := strings.TrimSpace(update.FeedID)
		if len(feedID) == 0 || len(feedID) > threatintel.MaximumFeedIDBytes {
			e.ledgerAppend("threat-intelligence.feed-policy", "request", "rejected")
			return e.FeedPolicy(), errors.New("feed policy feed identifier rejected")
		}
		if _, duplicate := seen[feedID]; duplicate {
			e.ledgerAppend("threat-intelligence.feed-policy", "request", "rejected")
			return e.FeedPolicy(), fmt.Errorf("duplicate feed policy entry for %q", feedID)
		}
		seen[feedID] = struct{}{}
		action, err := normalizeFeedAction(update.Action)
		if err != nil {
			e.ledgerAppend("threat-intelligence.feed-policy", "request", "rejected")
			return e.FeedPolicy(), err
		}
		changes = append(changes, threatintel.FeedActionChange{FeedKey: feedID, Action: action})
	}
	previous := e.feedPolicyBase()
	requestSummary := feedPolicyRequestSummary(updates) + ";reason-sha256=" + reasonDigest
	if e.ledger != nil {
		if err := e.ledger.Append("threat-intelligence.feed-policy", "request", requestSummary); err != nil {
			return e.FeedPolicy(), fmt.Errorf("feed policy evidence preflight failed: %w", err)
		}
	}
	now := time.Now().UTC()
	if _, err := e.feeds.SetFeedActions(changes, reasonDigest, now); err != nil {
		e.ledgerAppend("threat-intelligence.feed-policy", "change", "rejected")
		return e.FeedPolicy(), err
	}
	// Synchronous WFP verification attempt. Failure is not a fake success: the
	// response explicitly reports pending and the loop retries.
	status := e.feeds.Status()
	if status.BlockingIndicators > 0 {
		if applyErr := e.applyThreatEnforcement(ctx, status); applyErr != nil {
			e.ledgerAppend("threat-intelligence.feed-policy", "change", "pending-wfp-verification")
		} else {
			e.ledgerAppend("threat-intelligence.feed-policy", "change", "verified")
		}
	} else {
		e.ledgerAppend("threat-intelligence.feed-policy", "change", "pending-no-validated-blocking")
	}
	e.wakeIntelligence()
	result := e.FeedPolicy()
	result.PreviousEnforcementGeneration = previous
	result.EnforcementChanged = previous != result.EnforcementGeneration
	return result, nil
}

// feedPolicyBase returns the enforcement generation that is currently effective
// before an operator change.
func (e *Engine) feedPolicyBase() string {
	base := e.feeds.FeedPolicy()
	return base.EnforcementGeneration
}
