// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Per-feed action overrides (Windows Beta V5)
//
// The immutable catalog in catalog.go assigns every feed an authority. This file
// adds an operator-controlled, validated override layer that is applied when the
// in-memory index and the WFP enforcement projection are built. Downloaded feed
// snapshots (sources/*.json) keep the immutable catalog authority: the override
// layer never rewrites downloaded data, so data integrity and attribution stay
// auditable and protected-network subtraction continues to operate on the same
// validated indicators.
const (
	// FeedPolicySchemaVersion is the on-disk schema of the override store.
	FeedPolicySchemaVersion = 1
	feedPolicyFileName      = "feed-policy.json"
	// maximumFeedPolicyBytes bounds the override store before any decoding.
	maximumFeedPolicyBytes = 16 << 10
	// maximumFeedPolicyOverrides is a hard cap; the catalog is smaller.
	maximumFeedPolicyOverrides = 64
	// MaximumFeedIDBytes bounds an accepted feed identifier.
	MaximumFeedIDBytes = 32
)

const (
	feedPolicySourceDefault   = "DEFAULT"
	feedPolicySourcePersisted = "PERSISTED"
	feedPolicySourceInvalid   = "INVALID_DEFAULT"
	feedPolicyEntrySource     = "OVERRIDE"
)

// FeedPolicyOverride is one persisted operator override. Only the reason digest
// is stored, never the operator's free-text reason.
type FeedPolicyOverride struct {
	FeedKey      string    `json:"feedKey"`
	Action       Action    `json:"action"`
	UpdatedUTC   time.Time `json:"updatedUtc"`
	ReasonSHA256 string    `json:"reasonSha256,omitempty"`
}

// FeedActionChange requests one override transition. A nil Action resets the
// feed to its immutable catalog authority.
type FeedActionChange struct {
	FeedKey string
	Action  *Action
}

// FeedPolicyLimits publishes the validation envelope to the API layer.
type FeedPolicyLimits struct {
	MaxOverrides       int      `json:"maxOverrides"`
	MaximumFeedIDBytes int      `json:"maximumFeedIdBytes"`
	AllowedActions     []Action `json:"allowedActions"`
}

// FeedPolicyEntry is the effective authority of one feed.
type FeedPolicyEntry struct {
	FeedKey           string    `json:"feedId"`
	Name              string    `json:"name"`
	DefaultAction     Action    `json:"defaultAction"`
	ConfiguredAction  Action    `json:"configuredAction"`
	EffectiveAction   Action    `json:"effectiveAction"`
	Source            string    `json:"source"`
	UpdatedUTC        time.Time `json:"updatedUtc,omitempty"`
	Blocking          bool      `json:"blocking"`
	Indicators        int       `json:"indicators"`
	Ready             bool      `json:"ready"`
	FeedState         string    `json:"feedState"`
	EnforcementImpact string    `json:"enforcementImpact"`
}

// FeedPolicySnapshot is the read-only manager view of the effective feed
// authority. EnforcementChanged is true when the effective policy compiles a
// different WFP block set than the immutable catalog defaults would.
type FeedPolicySnapshot struct {
	SchemaVersion         int               `json:"schemaVersion"`
	StoreState            string            `json:"storeState"`
	StoreError            string            `json:"storeError,omitempty"`
	UpdatedUTC            time.Time         `json:"updatedUtc,omitempty"`
	Generation            string            `json:"generationSha256"`
	EnforcementGeneration string            `json:"enforcementGenerationSha256"`
	Indicators            int               `json:"indicators"`
	BlockingIndicators    int               `json:"blockingIndicators"`
	BlockingFeedsTotal    int               `json:"blockingFeedsTotal"`
	BlockingFeedsReady    int               `json:"blockingFeedsReady"`
	EnforcementChanged    bool              `json:"enforcementChanged"`
	Limits                FeedPolicyLimits  `json:"limits"`
	Entries               []FeedPolicyEntry `json:"feeds"`
}

type feedPolicyState struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Overrides     []FeedPolicyOverride `json:"overrides"`
	UpdatedUTC    time.Time            `json:"updatedUtc"`
	// MAC authenticates the canonical override set with the service-local feed
	// policy key, so a downgrade/promotion of a BLOCK feed cannot be injected by
	// editing the store (DP-FIND-004).
	MAC string `json:"mac"`
}

type feedPolicyMACPayload struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Overrides     []FeedPolicyOverride `json:"overrides"`
	UpdatedUTC    time.Time            `json:"updatedUtc"`
}

func feedPolicyStoreMAC(key []byte, payload feedPolicyMACPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, feedPolicyMACKey(key))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func canonicalFeedPolicyOverrides(overrides []FeedPolicyOverride) []FeedPolicyOverride {
	sorted := append([]FeedPolicyOverride(nil), overrides...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].FeedKey < sorted[right].FeedKey })
	return sorted
}

func feedPolicyPath(root string) string {
	return filepath.Join(root, feedPolicyFileName)
}

func allowedFeedActions() []Action {
	return []Action{ActionBlock, ActionCorrelateOnly, ActionAnnotateOnly}
}

func validFeedAction(action Action) bool {
	switch action {
	case ActionBlock, ActionCorrelateOnly, ActionAnnotateOnly:
		return true
	default:
		return false
	}
}

// FeedPolicyLimitsForAPI returns the validation envelope for API/UI layers.
func FeedPolicyLimitsForAPI() FeedPolicyLimits {
	maxOverrides := len(catalog)
	if maxOverrides > maximumFeedPolicyOverrides {
		maxOverrides = maximumFeedPolicyOverrides
	}
	return FeedPolicyLimits{MaxOverrides: maxOverrides, MaximumFeedIDBytes: MaximumFeedIDBytes, AllowedActions: allowedFeedActions()}
}

// readFeedPolicyStore validates the persisted override store without following
// links. A corrupt store is reported to the caller; it is never partially
// applied.
func readFeedPolicyStore(root string, key []byte) (feedPolicyState, error) {
	path := feedPolicyPath(root)
	info, err := os.Lstat(path)
	if err != nil {
		return feedPolicyState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return feedPolicyState{}, errors.New("feed policy store must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > maximumFeedPolicyBytes {
		return feedPolicyState{}, errors.New("feed policy store size rejected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return feedPolicyState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state feedPolicyState
	if err := decoder.Decode(&state); err != nil {
		return feedPolicyState{}, errors.New("feed policy store decoding rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return feedPolicyState{}, errors.New("feed policy store trailing data rejected")
	}
	if state.SchemaVersion != FeedPolicySchemaVersion || len(state.Overrides) > maximumFeedPolicyOverrides || len(state.Overrides) > len(catalog) {
		return feedPolicyState{}, errors.New("feed policy store schema rejected")
	}
	if len(key) != 32 || len(state.MAC) != 64 {
		return feedPolicyState{}, errors.New("feed policy store authentication is missing")
	}
	expectedMAC, macErr := feedPolicyStoreMAC(key, feedPolicyMACPayload{SchemaVersion: state.SchemaVersion, Overrides: canonicalFeedPolicyOverrides(state.Overrides), UpdatedUTC: state.UpdatedUTC})
	if macErr != nil || !signatureHMACEqual(expectedMAC, state.MAC) {
		return feedPolicyState{}, errors.New("feed policy store authentication rejected")
	}
	seen := make(map[string]struct{}, len(state.Overrides))
	for _, override := range state.Overrides {
		source, exists := sourceByKey(override.FeedKey)
		if !exists || override.FeedKey != source.Key || len(override.FeedKey) > MaximumFeedIDBytes {
			return feedPolicyState{}, errors.New("feed policy store feed identifier rejected")
		}
		if !validFeedAction(override.Action) {
			return feedPolicyState{}, errors.New("feed policy store action rejected")
		}
		if _, duplicate := seen[override.FeedKey]; duplicate {
			return feedPolicyState{}, errors.New("feed policy store duplicate feed rejected")
		}
		seen[override.FeedKey] = struct{}{}
		if override.ReasonSHA256 != "" && !validReasonDigest(override.ReasonSHA256) {
			return feedPolicyState{}, errors.New("feed policy store reason digest rejected")
		}
		if !override.UpdatedUTC.IsZero() && override.UpdatedUTC.After(time.Now().UTC().Add(24*time.Hour)) {
			return feedPolicyState{}, errors.New("feed policy store timestamp rejected")
		}
	}
	return state, nil
}

func validReasonDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// loadFeedPolicy restores the override layer. A missing file means catalog
// defaults; an unreadable/invalid file is preserved on disk untouched and
// reported as INVALID_DEFAULT while catalog defaults remain effective.
func (m *Manager) loadFeedPolicy() {
	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	m.overrides = make(map[string]FeedPolicyOverride, len(catalog))
	m.policySource = feedPolicySourceDefault
	m.policyUpdatedUTC = time.Time{}
	m.policyStoreError = ""
	state, err := readFeedPolicyStore(m.root, m.feedPolicyKey)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		m.policySource = feedPolicySourceInvalid
		m.policyStoreError = err.Error()
		return
	}
	for _, override := range state.Overrides {
		m.overrides[override.FeedKey] = override
	}
	m.policySource = feedPolicySourcePersisted
	m.policyUpdatedUTC = state.UpdatedUTC
}

// effectiveActionLocked resolves a feed key against the override layer while
// policyMu is held for reading or writing.
func (m *Manager) effectiveActionLocked(key string) Action {
	if override, exists := m.overrides[key]; exists {
		return override.Action
	}
	source, exists := sourceByKey(key)
	if !exists {
		return Action("")
	}
	return source.Action
}

// feedPolicyView returns a detached copy of the override layer for callers that
// must not hold policyMu while doing further work.
func (m *Manager) feedPolicyView() (map[string]FeedPolicyOverride, string, time.Time, string) {
	m.policyMu.RLock()
	defer m.policyMu.RUnlock()
	overrides := make(map[string]FeedPolicyOverride, len(m.overrides))
	for key, override := range m.overrides {
		overrides[key] = override
	}
	return overrides, m.policySource, m.policyUpdatedUTC, m.policyStoreError
}

// applyEffectiveActions clones the given snapshots and replaces each feed's
// authority with its effective action. Downloaded snapshots are never mutated.
func applyEffectiveActionsToSnapshots(snapshots map[string]sourceSnapshot, overrides map[string]FeedPolicyOverride) map[string]sourceSnapshot {
	result := make(map[string]sourceSnapshot, len(snapshots))
	for key, snapshot := range snapshots {
		if override, exists := overrides[key]; exists {
			snapshot.Action = override.Action
		}
		result[key] = snapshot
	}
	return result
}

// effectiveBlockingCoverage counts effective BLOCK feeds and how many of those
// have validated last-known-good indicators.
func effectiveBlockingCoverage(snapshots map[string]sourceSnapshot, overrides map[string]FeedPolicyOverride) (total, ready int) {
	for _, source := range catalog {
		action := source.Action
		if override, exists := overrides[source.Key]; exists {
			action = override.Action
		}
		if action != ActionBlock {
			continue
		}
		total++
		if snapshot, exists := snapshots[source.Key]; exists && len(snapshot.Indicators) > 0 {
			ready++
		}
	}
	return total, ready
}

// FeedPolicy returns the effective per-feed authority, the store state and the
// compiled generation counters. It performs no I/O.
func (m *Manager) FeedPolicy() FeedPolicySnapshot {
	limits := FeedPolicyLimitsForAPI()
	snapshot := FeedPolicySnapshot{SchemaVersion: FeedPolicySchemaVersion, StoreState: feedPolicySourceDefault, Limits: limits}
	if m == nil {
		snapshot.StoreState = feedPolicySourceInvalid
		snapshot.StoreError = "threat intelligence manager unavailable"
		snapshot.Entries = []FeedPolicyEntry{}
		return snapshot
	}
	overrides, policySource, policyUpdatedUTC, storeError := m.feedPolicyView()
	status := m.Status()
	index := m.index.Load()
	snapshot.StoreState = policySource
	snapshot.StoreError = storeError
	snapshot.UpdatedUTC = policyUpdatedUTC
	if index != nil {
		snapshot.Generation = index.generation
		snapshot.Indicators = index.indicators
		snapshot.BlockingIndicators = index.blocking
		if index.blocking > 0 {
			// An empty block projection has no meaningful enforcement
			// generation; reporting the hash of an empty set would imply an
			// enforcement authority that does not exist.
			snapshot.EnforcementGeneration = index.enforcementGeneration
		}
	}
	states := make(map[string]FeedState, len(status.Feeds))
	for _, feed := range status.Feeds {
		states[feed.Key] = feed
	}
	entries := make([]FeedPolicyEntry, 0, len(catalog))
	enforcementChanged := false
	for _, feedSource := range catalog {
		entry := FeedPolicyEntry{FeedKey: feedSource.Key, Name: feedSource.Name, DefaultAction: feedSource.Action, ConfiguredAction: feedSource.Action, EffectiveAction: feedSource.Action, Source: feedPolicySourceDefault}
		if override, exists := overrides[feedSource.Key]; exists {
			entry.ConfiguredAction = override.Action
			entry.EffectiveAction = override.Action
			entry.Source = feedPolicyEntrySource
			entry.UpdatedUTC = override.UpdatedUTC
		}
		entry.Blocking = entry.EffectiveAction == ActionBlock
		entry.EnforcementImpact = feedEnforcementImpact(entry.DefaultAction, entry.EffectiveAction)
		if feedState, exists := states[feedSource.Key]; exists {
			entry.Indicators = feedState.Indicators
			entry.FeedState = feedState.State
			entry.Ready = feedState.Indicators > 0 && (feedState.State == "CURRENT" || feedState.State == "STALE" || feedState.State == "CACHED")
		}
		entryBlocking := entry.EffectiveAction == ActionBlock
		if entry.Indicators > 0 && (entry.DefaultAction == ActionBlock) != entryBlocking {
			enforcementChanged = true
		}
		if entryBlocking {
			snapshot.BlockingFeedsTotal++
			if entry.Ready {
				snapshot.BlockingFeedsReady++
			}
		}
		entries = append(entries, entry)
	}
	snapshot.EnforcementChanged = enforcementChanged
	snapshot.Entries = entries
	return snapshot
}

func feedEnforcementImpact(defaultAction, effectiveAction Action) string {
	switch {
	case defaultAction == effectiveAction:
		return "NONE"
	case defaultAction != ActionBlock && effectiveAction == ActionBlock:
		return "ADDS_BLOCK"
	case defaultAction == ActionBlock && effectiveAction != ActionBlock:
		return "REMOVES_BLOCK"
	default:
		return "CORRELATION_ONLY"
	}
}

// SetFeedActions validates, persists and activates a set of per-feed overrides.
//
// Fail-closed rules:
//   - unknown feeds, unsupported actions, duplicates and oversized requests are
//     rejected before any change;
//   - an override that would leave no compiled blocking indicators is rejected;
//   - an override is only accepted when every effective BLOCK feed has validated
//     last-known-good indicators, so a verified WFP generation can actually be
//     compiled and applied;
//   - persistence and enforcement-snapshot failures are rolled back so memory
//     and disk cannot disagree.
func (m *Manager) SetFeedActions(changes []FeedActionChange, reasonSHA256 string, updatedUTC time.Time) (FeedPolicySnapshot, error) {
	if m == nil {
		return FeedPolicySnapshot{}, errors.New("threat intelligence manager unavailable")
	}
	if len(changes) == 0 || len(changes) > len(catalog) || len(changes) > maximumFeedPolicyOverrides {
		return FeedPolicySnapshot{}, errors.New("feed policy change count rejected")
	}
	if reasonSHA256 != "" && !validReasonDigest(reasonSHA256) {
		return FeedPolicySnapshot{}, errors.New("feed policy reason digest rejected")
	}
	if !m.syncMu.TryLock() {
		return FeedPolicySnapshot{}, ErrSyncInProgress
	}
	defer m.syncMu.Unlock()

	previousOverrides, _, _, _ := m.feedPolicyView()
	nextOverrides := make(map[string]FeedPolicyOverride, len(previousOverrides)+len(changes))
	for key, override := range previousOverrides {
		nextOverrides[key] = override
	}
	seen := make(map[string]struct{}, len(changes))
	for _, change := range changes {
		if len(change.FeedKey) == 0 || len(change.FeedKey) > MaximumFeedIDBytes {
			return FeedPolicySnapshot{}, errors.New("feed policy feed identifier rejected")
		}
		if _, duplicate := seen[change.FeedKey]; duplicate {
			return FeedPolicySnapshot{}, errors.New("feed policy duplicate feed rejected")
		}
		seen[change.FeedKey] = struct{}{}
		source, exists := sourceByKey(change.FeedKey)
		if !exists {
			return FeedPolicySnapshot{}, fmt.Errorf("unknown threat feed %q", change.FeedKey)
		}
		if change.Action == nil || *change.Action == source.Action {
			delete(nextOverrides, change.FeedKey)
			continue
		}
		if !validFeedAction(*change.Action) {
			return FeedPolicySnapshot{}, errors.New("feed policy action rejected")
		}
		nextOverrides[change.FeedKey] = FeedPolicyOverride{FeedKey: change.FeedKey, Action: *change.Action, UpdatedUTC: updatedUTC.UTC(), ReasonSHA256: reasonSHA256}
	}

	protectedPolicy, protectedPrefixes := m.protectedSnapshot()
	index := buildIndex(applyEffectiveActionsToSnapshots(m.snapshots, nextOverrides))
	if err := index.compileEnforcement(protectedPrefixes); err != nil {
		return FeedPolicySnapshot{}, err
	}
	if index.blocking > maximumEnforcementIndicators {
		return FeedPolicySnapshot{}, errors.New("blocking threat intelligence boundary exceeded")
	}
	blockingTotal, blockingReady := effectiveBlockingCoverage(m.snapshots, nextOverrides)
	if index.indicators > 0 {
		if index.blocking == 0 {
			return FeedPolicySnapshot{}, errors.New("feed policy would remove all blocking enforcement indicators")
		}
		if blockingTotal <= 0 || blockingReady != blockingTotal {
			return FeedPolicySnapshot{}, fmt.Errorf("feed policy requires validated indicators for all %d blocking feeds (%d ready); synchronize feeds first", blockingTotal, blockingReady)
		}
	}

	nextPayload, marshalErr := marshalFeedPolicyState(nextOverrides, updatedUTC, m.feedPolicyKey)
	if marshalErr != nil {
		return FeedPolicySnapshot{}, marshalErr
	}
	// Preserve the exact previous file bytes so a failed enforcement-snapshot
	// commit can restore the store without inventing a new representation. This
	// also keeps an unreadable store byte-identical for forensic inspection.
	previousFile, previousFileErr := os.ReadFile(feedPolicyPath(m.root))
	previousFileExisted := previousFileErr == nil && len(previousFile) <= maximumFeedPolicyBytes
	if previousFileErr != nil && !errors.Is(previousFileErr, os.ErrNotExist) {
		previousFileExisted = false
	}
	if err := atomicWrite(feedPolicyPath(m.root), nextPayload); err != nil {
		return FeedPolicySnapshot{}, fmt.Errorf("feed policy persistence: %w", err)
	}
	rollbackStore := func() {
		if previousFileExisted {
			_ = atomicWrite(feedPolicyPath(m.root), previousFile)
			return
		}
		_ = os.Remove(feedPolicyPath(m.root))
	}
	if index.indicators > 0 {
		if err := writeEnforcementSnapshot(m.root, updatedUTC, index, blockingReady, protectedPolicy); err != nil {
			rollbackStore()
			return FeedPolicySnapshot{}, fmt.Errorf("feed policy enforcement snapshot: %w", err)
		}
	}
	m.policyMu.Lock()
	m.overrides = nextOverrides
	m.policySource = feedPolicySourcePersisted
	m.policyUpdatedUTC = updatedUTC.UTC()
	m.policyStoreError = ""
	m.policyMu.Unlock()
	m.index.Store(index)
	m.applyFeedPolicyToStatus(index, blockingTotal, blockingReady)
	return m.FeedPolicy(), nil
}

func marshalFeedPolicyState(overrides map[string]FeedPolicyOverride, updatedUTC time.Time, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("feed policy key rejected")
	}
	normalized := make([]FeedPolicyOverride, 0, len(overrides))
	for _, override := range overrides {
		normalized = append(normalized, override)
	}
	normalized = canonicalFeedPolicyOverrides(normalized)
	updatedUTC = updatedUTC.UTC()
	payload := feedPolicyMACPayload{SchemaVersion: FeedPolicySchemaVersion, Overrides: normalized, UpdatedUTC: updatedUTC}
	mac, err := feedPolicyStoreMAC(key, payload)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(feedPolicyState{SchemaVersion: payload.SchemaVersion, Overrides: normalized, UpdatedUTC: updatedUTC, MAC: mac})
	if err != nil {
		return nil, err
	}
	if len(raw) > maximumFeedPolicyBytes {
		return nil, errors.New("feed policy store boundary exceeded")
	}
	return append(raw, '\n'), nil
}

// applyFeedPolicyToStatus re-projects the persisted status counters after an
// override change. Feed state (CURRENT/STALE/...) and timestamps are preserved.
func (m *Manager) applyFeedPolicyToStatus(index *Index, blockingTotal, blockingReady int) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	if index != nil {
		m.status.Indicators = index.indicators
		m.status.BlockingIndicators = index.blocking
		m.status.CorrelationIndicators = index.correlation
		m.status.AnnotationIndicators = index.annotation
		m.status.Generation = index.generation
		m.status.EnforcementGeneration = index.enforcementGeneration
	}
	m.status.BlockingFeedsTotal = blockingTotal
	m.status.BlockingFeedsReady = blockingReady
}
