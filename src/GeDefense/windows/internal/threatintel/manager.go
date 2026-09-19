// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maximumAggregateIndicators = 750000
	minimumRetainedRatio       = 10
)

var ErrSyncInProgress = errors.New("threat intelligence synchronization already in progress")

type Manager struct {
	root              string
	client            *http.Client
	syncMu            sync.Mutex
	statusMu          sync.RWMutex
	protectedMu       sync.RWMutex
	status            Status
	snapshots         map[string]sourceSnapshot
	protectedPolicy   ProtectedNetworkPolicy
	protectedPrefixes []netip.Prefix
	protectedTrie     prefixTrie
	protectedKey      []byte
	index             atomic.Pointer[Index]
}

func NewManager(root string) (*Manager, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("threat intelligence root must be absolute")
	}
	if err := os.MkdirAll(filepath.Join(root, "sources"), 0700); err != nil {
		return nil, err
	}
	protectedKey, err := loadOrCreateProtectedPolicyKey(root)
	if err != nil {
		return nil, fmt.Errorf("protected network policy key: %w", err)
	}
	protectedPolicy, protectedPrefixes, err := loadProtectedPolicy(root, protectedKey)
	if err != nil {
		return nil, fmt.Errorf("protected network policy: %w", err)
	}
	transport := &http.Transport{
		DialContext:            hardenedDialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        2,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	manager := &Manager{
		root: root,
		client: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		snapshots:         make(map[string]sourceSnapshot, len(catalog)),
		protectedPolicy:   protectedPolicy,
		protectedPrefixes: protectedPrefixes,
		protectedTrie:     buildPrefixTrie(protectedPrefixes),
		protectedKey:      protectedKey,
		status:            Status{State: "INITIALIZING", Feeds: make([]FeedState, 0, len(catalog)), ProtectedPrefixes: len(protectedPolicy.Prefixes), ProtectionGeneration: protectedPolicy.GenerationSHA256},
	}
	manager.loadCached()
	return manager, nil
}

func (m *Manager) Sync(ctx context.Context) error {
	if ctx == nil {
		return errors.New("threat intelligence synchronization requires context")
	}
	if !m.syncMu.TryLock() {
		return ErrSyncInProgress
	}
	defer m.syncMu.Unlock()

	attempt := time.Now().UTC()
	candidate := cloneSnapshots(m.snapshots)
	states := make([]FeedState, 0, len(catalog))
	fresh := 0
	blockingReady := 0
	blockingTotal := 0
	aggregate := 0
	for _, source := range catalog {
		if source.Action == ActionBlock {
			blockingTotal++
		}
		previous, hasPrevious := candidate[source.Key]
		state := FeedState{Key: source.Key, Name: source.Name, Action: source.Action, LastAttemptUTC: attempt}
		prefixes, attribution, err := m.fetchSource(ctx, source)
		if err == nil && hasPrevious && suspiciousShrink(len(previous.Indicators), len(prefixes)) {
			err = errors.New("threat feed shrinkage safety gate rejected generation")
		}
		if err == nil {
			indicators := make([]string, 0, len(prefixes))
			for _, prefix := range prefixes {
				indicators = append(indicators, prefix.String())
			}
			sort.Strings(indicators)
			snapshot := sourceSnapshot{
				SchemaVersion:    SchemaVersion,
				Key:              source.Key,
				GeneratedUTC:     attempt,
				Action:           source.Action,
				Attribution:      attribution,
				GenerationSHA256: digestIndicators(source.Key, source.Action, indicators),
				Indicators:       indicators,
			}
			if writeErr := writeSourceSnapshot(m.root, snapshot); writeErr != nil {
				err = writeErr
			} else {
				candidate[source.Key] = snapshot
				state.State = "CURRENT"
				state.Indicators = len(indicators)
				state.LastSuccessUTC = attempt
				fresh++
			}
		}
		if err != nil {
			if hasPrevious {
				state.State = "STALE"
				state.Indicators = len(previous.Indicators)
				state.LastSuccessUTC = previous.GeneratedUTC
				state.Error = "last-known-good generation retained"
			} else {
				state.State = "UNAVAILABLE"
				state.Error = "no validated generation available"
			}
		}
		if source.Action == ActionBlock && state.Indicators > 0 && (state.State == "CURRENT" || state.State == "STALE") {
			blockingReady++
		}
		aggregate += state.Indicators
		if aggregate > maximumAggregateIndicators {
			m.fail(attempt, errors.New("aggregate threat intelligence boundary exceeded"))
			return errors.New("aggregate threat intelligence boundary exceeded")
		}
		states = append(states, state)
	}

	index := buildIndex(candidate)
	protectedPolicy, protectedPrefixes := m.protectedSnapshot()
	if err := index.compileEnforcement(protectedPrefixes); err != nil {
		m.fail(attempt, err)
		return err
	}
	if index.blocking > maximumEnforcementIndicators {
		err := errors.New("blocking threat intelligence boundary exceeded")
		m.fail(attempt, err)
		return err
	}
	if index.blocking == 0 {
		err := errors.New("no validated blocking threat intelligence is available")
		m.fail(attempt, err)
		return err
	}
	if fresh == 0 {
		err := errors.New("no threat intelligence feed refreshed")
		m.fail(attempt, err)
		return err
	}
	if err := writeEnforcementSnapshot(m.root, attempt, index, blockingReady, protectedPolicy); err != nil {
		m.fail(attempt, err)
		return err
	}

	m.snapshots = candidate
	m.index.Store(index)
	state := "CURRENT"
	errorText := ""
	nextSync := attempt.Add(SyncInterval)
	if fresh != len(catalog) {
		state = "DEGRADED"
		errorText = fmt.Sprintf("%d of %d feeds refreshed; last-known-good data retained where available", fresh, len(catalog))
		nextSync = attempt.Add(FailureRetryInterval)
	}
	m.setStatus(Status{
		LastAttemptUTC:        attempt,
		LastSuccessUTC:        attempt,
		NextSyncUTC:           nextSync,
		Indicators:            index.indicators,
		BlockingIndicators:    index.blocking,
		BlockingFeedsReady:    blockingReady,
		BlockingFeedsTotal:    blockingTotal,
		CorrelationIndicators: index.correlation,
		AnnotationIndicators:  index.annotation,
		Generation:            index.generation,
		EnforcementGeneration: index.enforcementGeneration,
		ProtectedPrefixes:     len(protectedPolicy.Prefixes),
		ProtectionGeneration:  protectedPolicy.GenerationSHA256,
		State:                 state,
		Error:                 errorText,
		Feeds:                 states,
	})
	return nil
}

func (m *Manager) Lookup(address netip.Addr) Match {
	index := m.index.Load()
	if index == nil {
		return Match{}
	}
	match := index.Lookup(address)
	if !match.Found || !address.IsValid() {
		return match
	}
	address = address.Unmap()
	prefix := netip.PrefixFrom(address, address.BitLen())
	m.protectedMu.RLock()
	_, covered := m.protectedTrie.nodeFor(prefix)
	m.protectedMu.RUnlock()
	match.Protected = covered
	return match
}

func (m *Manager) Contains(address netip.Addr) bool {
	return m.Lookup(address).Found
}

func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	status := m.status
	status.Feeds = append([]FeedState(nil), m.status.Feeds...)
	return status
}

func (m *Manager) SnapshotPath() string {
	return enforcementSnapshotPath(m.root)
}

func (m *Manager) ProtectedNetworkPolicy() ProtectedNetworkPolicy {
	if m == nil {
		return protectedPolicyFromPrefixes(nil, time.Time{})
	}
	m.protectedMu.RLock()
	defer m.protectedMu.RUnlock()
	policy := m.protectedPolicy
	policy.Prefixes = append([]string(nil), m.protectedPolicy.Prefixes...)
	return policy
}

func (m *Manager) SetProtectedPrefixes(values []string) (ProtectedNetworkPolicy, error) {
	if m == nil {
		return ProtectedNetworkPolicy{}, errors.New("threat intelligence manager unavailable")
	}
	if !m.syncMu.TryLock() {
		return ProtectedNetworkPolicy{}, ErrSyncInProgress
	}
	defer m.syncMu.Unlock()

	prefixes, _, err := normalizeProtectedPrefixes(values)
	if err != nil {
		return ProtectedNetworkPolicy{}, err
	}
	previousPolicy, previousPrefixes := m.protectedSnapshot()
	updatedUTC := time.Now().UTC()
	index := buildIndex(m.snapshots)
	if err := index.compileEnforcement(prefixes); err != nil {
		return ProtectedNetworkPolicy{}, err
	}
	blockingReady := blockingReadyCount(m.snapshots)
	if index.indicators > 0 && (index.blocking == 0 || blockingReady == 0) {
		return ProtectedNetworkPolicy{}, errors.New("protected network policy would remove all blocking enforcement indicators")
	}

	persistedPolicy, err := writeProtectedPolicy(m.root, m.protectedKey, prefixes, updatedUTC)
	if err != nil {
		return ProtectedNetworkPolicy{}, err
	}
	if index.indicators > 0 {
		if err := writeEnforcementSnapshot(m.root, updatedUTC, index, blockingReady, persistedPolicy); err != nil {
			rollbackErr := restoreProtectedPolicy(m.root, m.protectedKey, previousPolicy, previousPrefixes)
			m.markProtectionPolicyStatus(previousPolicy, err)
			if rollbackErr != nil {
				return previousPolicy, fmt.Errorf("protected network enforcement snapshot failed and policy rollback failed: %w", errors.Join(err, rollbackErr))
			}
			return previousPolicy, err
		}
	}

	m.protectedMu.Lock()
	m.protectedPolicy = persistedPolicy
	m.protectedPrefixes = append([]netip.Prefix(nil), prefixes...)
	m.protectedTrie = buildPrefixTrie(prefixes)
	m.protectedMu.Unlock()
	if index.indicators > 0 {
		m.index.Store(index)
	}
	m.markProtectionPolicyStatus(persistedPolicy, nil)
	return persistedPolicy, nil
}

func restoreProtectedPolicy(root string, key []byte, policy ProtectedNetworkPolicy, prefixes []netip.Prefix) error {
	if policy.UpdatedUTC.IsZero() && len(policy.Prefixes) == 0 {
		err := os.Remove(protectedPolicyPath(root))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	restored, err := writeProtectedPolicy(root, key, prefixes, policy.UpdatedUTC)
	if err != nil {
		return err
	}
	if !fixedHexEqual(restored.GenerationSHA256, policy.GenerationSHA256) {
		return errors.New("protected network policy rollback generation rejected")
	}
	return nil
}

func (m *Manager) protectedSnapshot() (ProtectedNetworkPolicy, []netip.Prefix) {
	m.protectedMu.RLock()
	defer m.protectedMu.RUnlock()
	policy := m.protectedPolicy
	policy.Prefixes = append([]string(nil), m.protectedPolicy.Prefixes...)
	prefixes := append([]netip.Prefix(nil), m.protectedPrefixes...)
	return policy, prefixes
}

func (m *Manager) markProtectionPolicyStatus(policy ProtectedNetworkPolicy, policyErr error) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	m.status.ProtectedPrefixes = len(policy.Prefixes)
	m.status.ProtectionGeneration = policy.GenerationSHA256
	if current := m.index.Load(); current != nil {
		m.status.BlockingIndicators = current.blocking
		m.status.EnforcementGeneration = current.enforcementGeneration
	}
	if policyErr != nil {
		m.status.State = "DEGRADED"
		m.status.Error = "protected network policy changed but enforcement reconciliation is incomplete"
		m.status.NextSyncUTC = time.Now().UTC()
	}
}

func blockingReadyCount(snapshots map[string]sourceSnapshot) int {
	ready := 0
	for _, source := range catalog {
		if source.Action != ActionBlock {
			continue
		}
		if snapshot, ok := snapshots[source.Key]; ok && len(snapshot.Indicators) > 0 {
			ready++
		}
	}
	return ready
}

func (m *Manager) fetchSource(ctx context.Context, source Source) ([]netip.Prefix, Attribution, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, Attribution{}, err
	}
	req.Header.Set("Accept", "application/json, text/json, text/plain, application/octet-stream")
	req.Header.Set("User-Agent", "VGT-GeDefense-Windows-ThreatIntel/4.1")
	response, err := m.client.Do(req)
	if err != nil {
		return nil, Attribution{}, fmt.Errorf("fetch %s: %w", source.Name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, Attribution{}, fmt.Errorf("fetch %s: HTTP %d", source.Name, response.StatusCode)
	}
	if contentType := strings.TrimSpace(response.Header.Get("Content-Type")); contentType != "" {
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr == nil && strings.EqualFold(mediaType, "text/html") {
			return nil, Attribution{}, errors.New("threat feed returned HTML content")
		}
	}
	limit := source.MaximumBytes
	if limit <= 0 || limit > defaultMaximumFeedBytes {
		limit = defaultMaximumFeedBytes
	}
	if response.ContentLength > limit {
		return nil, Attribution{}, errors.New("threat feed declared size boundary rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, Attribution{}, fmt.Errorf("read %s: %w", source.Name, err)
	}
	if len(body) == 0 || int64(len(body)) > limit {
		return nil, Attribution{}, errors.New("threat feed size boundary rejected")
	}
	trimmed := strings.TrimSpace(string(body[:min(len(body), 256)]))
	if strings.HasPrefix(strings.ToLower(trimmed), "<!doctype html") || strings.HasPrefix(strings.ToLower(trimmed), "<html") {
		return nil, Attribution{}, errors.New("threat feed HTML body rejected")
	}
	return parseSource(source, body)
}

func (m *Manager) loadCached() {
	states := make([]FeedState, 0, len(catalog))
	blockingReady := 0
	blockingTotal := 0
	aggregate := 0
	for _, source := range catalog {
		if source.Action == ActionBlock {
			blockingTotal++
		}
		snapshot, err := readSourceSnapshot(m.root, source)
		if err != nil {
			states = append(states, FeedState{Key: source.Key, Name: source.Name, Action: source.Action, State: "UNAVAILABLE"})
			continue
		}
		aggregate += len(snapshot.Indicators)
		if aggregate > maximumAggregateIndicators {
			m.snapshots = make(map[string]sourceSnapshot, len(catalog))
			m.setStatus(Status{State: "FAILED", Error: "cached threat intelligence boundary rejected", BlockingFeedsTotal: blockingTotal, Feeds: states})
			return
		}
		m.snapshots[source.Key] = snapshot
		if source.Action == ActionBlock {
			blockingReady++
		}
		states = append(states, FeedState{Key: source.Key, Name: source.Name, Action: source.Action, State: "CACHED", Indicators: len(snapshot.Indicators), LastSuccessUTC: snapshot.GeneratedUTC})
	}
	index := buildIndex(m.snapshots)
	protectedPolicy, protectedPrefixes := m.protectedSnapshot()
	if err := index.compileEnforcement(protectedPrefixes); err != nil {
		m.snapshots = make(map[string]sourceSnapshot, len(catalog))
		m.setStatus(Status{State: "FAILED", Error: "cached protected-network compilation rejected", BlockingFeedsTotal: blockingTotal, ProtectedPrefixes: len(protectedPolicy.Prefixes), ProtectionGeneration: protectedPolicy.GenerationSHA256, Feeds: states})
		return
	}
	if index.blocking > maximumEnforcementIndicators {
		m.snapshots = make(map[string]sourceSnapshot, len(catalog))
		m.setStatus(Status{State: "FAILED", Error: "cached blocking threat intelligence boundary rejected", BlockingFeedsTotal: blockingTotal, Feeds: states})
		return
	}
	if index.indicators == 0 {
		m.setStatus(Status{State: "INITIALIZING", BlockingFeedsTotal: blockingTotal, Feeds: states})
		return
	}
	m.index.Store(index)
	latest := latestSnapshotTime(m.snapshots)
	nextSync := latest.Add(SyncInterval)
	state := "CACHED"
	errorText := ""
	if blockingReady != blockingTotal || index.blocking == 0 {
		nextSync = time.Now().UTC()
		state = "DEGRADED"
		errorText = "blocking coverage incomplete; immediate synchronization required"
	} else if err := writeEnforcementSnapshot(m.root, latest, index, blockingReady, protectedPolicy); err != nil {
		nextSync = time.Now().UTC()
		state = "DEGRADED"
		errorText = "cached enforcement snapshot could not be reconstructed"
	}
	m.setStatus(Status{
		LastSuccessUTC:        latest,
		NextSyncUTC:           nextSync,
		Indicators:            index.indicators,
		BlockingIndicators:    index.blocking,
		BlockingFeedsReady:    blockingReady,
		BlockingFeedsTotal:    blockingTotal,
		CorrelationIndicators: index.correlation,
		AnnotationIndicators:  index.annotation,
		Generation:            index.generation,
		EnforcementGeneration: index.enforcementGeneration,
		ProtectedPrefixes:     len(protectedPolicy.Prefixes),
		ProtectionGeneration:  protectedPolicy.GenerationSHA256,
		State:                 state,
		Error:                 errorText,
		Feeds:                 states,
	})
}

func (m *Manager) fail(attempt time.Time, err error) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	m.status.LastAttemptUTC = attempt
	m.status.NextSyncUTC = attempt.Add(FailureRetryInterval)
	if m.status.Indicators > 0 {
		m.status.State = "STALE"
	} else {
		m.status.State = "FAILED"
	}
	m.status.Error = "synchronization failed; validated last-known-good data remains active when available"
}

func (m *Manager) setStatus(status Status) {
	m.statusMu.Lock()
	m.status = status
	m.statusMu.Unlock()
}

func hardenedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("threat feed endpoint rejected")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("threat feed DNS resolution failed")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, resolved := range addresses {
		addr := netip.AddrFrom16(resolved.As16()).Unmap()
		if !validFetchAddress(addr) {
			continue
		}
		if network == "tcp4" && !addr.Is4() {
			continue
		}
		if network == "tcp6" && !addr.Is6() {
			continue
		}
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, fmt.Errorf("threat feed connection failed: %w", lastErr)
	}
	return nil, errors.New("threat feed DNS resolved only to rejected address space")
}

func validFetchAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	prefix := netip.PrefixFrom(address, address.BitLen())
	for _, protected := range protectedThreatRanges {
		if prefixesOverlap(prefix, protected) {
			return false
		}
	}
	return true
}

func cloneSnapshots(source map[string]sourceSnapshot) map[string]sourceSnapshot {
	result := make(map[string]sourceSnapshot, len(source))
	for key, snapshot := range source {
		result[key] = snapshot
	}
	return result
}

func suspiciousShrink(previous, current int) bool {
	if previous < 100 || current >= previous {
		return false
	}
	return current*100 < previous*minimumRetainedRatio
}

func latestSnapshotTime(values map[string]sourceSnapshot) time.Time {
	var latest time.Time
	for _, snapshot := range values {
		if snapshot.GeneratedUTC.After(latest) {
			latest = snapshot.GeneratedUTC
		}
	}
	return latest
}
