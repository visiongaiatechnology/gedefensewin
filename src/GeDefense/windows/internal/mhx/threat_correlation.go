// STATUS: PLATIN VGT SUPREME
package mhx

import "time"

const (
	// threatHitTTL bounds how long a network threat-intelligence hit keeps
	// contributing to the fair behavioural score of the process that caused it.
	threatHitTTL = 10 * time.Minute
	// maxThreatHits bounds the per-PID threat correlation map.
	maxThreatHits = 1024
)

// recordThreatHitLocked records that pid contacted threat-intelligence
// infrastructure. Callers must hold e.mu.
func (e *Engine) recordThreatHitLocked(pid uint32, at time.Time) {
	if pid <= 4 {
		return
	}
	if e.threatHits == nil {
		e.threatHits = make(map[uint32]time.Time, 64)
	}
	e.threatHits[pid] = at
	if len(e.threatHits) > maxThreatHits {
		cutoff := at.Add(-threatHitTTL)
		for key, seen := range e.threatHits {
			if seen.Before(cutoff) {
				delete(e.threatHits, key)
			}
		}
		if len(e.threatHits) > maxThreatHits {
			// Bounded emergency reset: correlation is enrichment, not evidence
			// integrity. Dropping it can only lower the score, never raise it.
			e.threatHits = make(map[uint32]time.Time, 64)
		}
	}
}

// pidHasRecentThreatHit reports whether pid produced a network threat hit
// recently. It feeds the fair behavioural score with a real signal instead of a
// hard-coded false.
func (e *Engine) pidHasRecentThreatHit(pid uint32) bool {
	if pid <= 4 {
		return false
	}
	e.mu.RLock()
	seen, found := e.threatHits[pid]
	e.mu.RUnlock()
	if !found {
		return false
	}
	return time.Since(seen) <= threatHitTTL
}

// purgeThreatHitsLocked drops expired threat correlations. Callers must hold
// e.mu.
func (e *Engine) purgeThreatHitsLocked(now time.Time) {
	if len(e.threatHits) == 0 {
		return
	}
	cutoff := now.Add(-threatHitTTL)
	for pid, seen := range e.threatHits {
		if seen.Before(cutoff) {
			delete(e.threatHits, pid)
		}
	}
}
