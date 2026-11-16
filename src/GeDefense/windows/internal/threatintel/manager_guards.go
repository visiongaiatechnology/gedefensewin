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
// an expired generation, a detected clock rollback or an unavailable signed feed
// authority into a fail-closed status: blocking counters and the enforcement
// generation are withdrawn, so the MHX layer refuses to apply a stale or
// untrusted rule generation.
//
// FIND-WIN-015: without a verified signed-authority key ring the status is
// explicitly UNVERIFIED / DISABLED_UNAUTHORIZED. Feed data remains visible for
// display and audit as ANNOTATE_ONLY, but no status field can advertise blocking
// enforcement. A rejected clock high-water anchor is surfaced through
// FeedClockError and also withdraws enforcement (fail closed).
func (m *Manager) applyFreshnessAndAuthenticity(status Status) Status {
	now := m.effectiveNowUTC()
	maxAge := m.maxFeedAge()
	rollback := m.clockRollbackDetected()
	clockError := m.clockErrorText()
	authorityAvailable := m.authorityEnforcementAvailable()
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
	if !authorityAvailable {
		// Fail closed independently of freshness: unsigned/unverified data may be
		// displayed and audited, never enforced.
		status.BlockingIndicators = 0
		status.BlockingFeedsReady = 0
		status.BlockingFeedsTotal = 0
		status.EnforcementGeneration = ""
		if status.State == "CURRENT" || status.State == "CACHED" {
			status.State = "DEGRADED"
		}
	}
	authenticity, enforcement, authorityDetail, keys, sequence := m.authorityStatus()
	status.FeedAuthenticity = authenticity
	status.FeedEnforcement = enforcement
	status.FeedAuthorityError = authorityDetail
	status.FeedAuthorityKeys = keys
	status.FeedAuthoritySequence = sequence
	if !authorityAvailable && status.Error == "" {
		status.Error = authorityDetail
	}
	if clockError != "" {
		status.FeedClockError = clockError
		if status.Error == "" {
			status.Error = clockError
		}
	}
	m.clockMu.RLock()
	status.FeedClockRollback = m.clockRollback
	m.clockMu.RUnlock()
	status.MaxFeedAgeSeconds = int(maxAge / time.Second)
	return status
}
