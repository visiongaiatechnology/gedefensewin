// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"time"
)

// snapshotExpired implements the hard feed freshness TTL (DP-FIND-003). A
// generation older than maxFeedAge is never treated as blocking-ready again.
func (m *Manager) snapshotExpired(snapshot sourceSnapshot, now time.Time) bool {
	if snapshot.GeneratedUTC.IsZero() {
		return true
	}
	return now.Sub(snapshot.GeneratedUTC) > m.maxFeedAge()
}

// applyFeedAuthorityState projects the signed attestation of one generation into
// the per-feed status record.
func applyFeedAuthorityState(state *FeedState, snapshot *sourceSnapshot) {
	if state == nil || snapshot == nil || snapshot.Authority == nil {
		return
	}
	attestation, ok := authorityAttestationFor(snapshot.Authority, snapshot.Key)
	if !ok {
		return
	}
	state.AuthorityVerified = true
	state.AuthoritySequence = attestation.Sequence
	state.AuthorityValidUntilUTC = attestation.ValidUntilUTC
}

// applyFreshnessAndAuthenticity is the read-time safety projection. It converts
// an expired generation or a detected clock rollback into a fail-closed status:
// blocking counters and the enforcement generation are withdrawn, so the MHX
// layer refuses to apply a stale or untrusted rule generation.
func (m *Manager) applyFreshnessAndAuthenticity(status Status) Status {
	now := m.effectiveNowUTC()
	maxAge := m.maxFeedAge()
	rollback := m.clockRollbackDetected()
	expiredBlocking := false
	for index := range status.Feeds {
		feed := &status.Feeds[index]
		if feed.LastSuccessUTC.IsZero() {
			continue
		}
		if rollback || now.Sub(feed.LastSuccessUTC) > maxAge {
			feed.State = "EXPIRED"
			feed.Error = "feed generation exceeds the hard freshness TTL"
			feed.Indicators = 0
			if feed.EffectiveAction == ActionBlock {
				expiredBlocking = true
			}
		}
	}
	if expiredBlocking || rollback {
		status.BlockingIndicators = 0
		status.BlockingFeedsReady = 0
		status.EnforcementGeneration = ""
		if status.State == "CURRENT" || status.State == "CACHED" || status.State == "DEGRADED" {
			status.State = "DEGRADED"
		}
		if rollback {
			status.Error = "wall-clock rollback detected: feed freshness is not trusted; blocking enforcement withdrawn"
		} else {
			status.Error = "hard feed freshness TTL exceeded: stale blocking generations are not enforced"
		}
	}
	m.authorityMu.RLock()
	status.FeedAuthenticity = feedAuthenticityUnconfigured
	if m.authorityConfigured {
		status.FeedAuthenticity = feedAuthenticityEnforced
		if m.authorityError != "" {
			status.FeedAuthenticity = feedAuthenticityFailed
		}
	}
	status.FeedAuthorityKeys = len(m.authorityKeys)
	status.FeedAuthoritySequence = m.authorityState.LastSequence
	status.FeedAuthorityError = m.authorityError
	m.authorityMu.RUnlock()
	status.FeedClockRollback = rollback
	status.MaxFeedAgeSeconds = int(maxAge / time.Second)
	return status
}
