// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

func (e *Engine) SyncFeeds(ctx context.Context) error {
	if err := e.feeds.Sync(ctx); err != nil {
		_ = e.ledger.Append("mhx.intelligence", "12h-sync", "failed")
		return err
	}
	status := e.feeds.Status()
	if err := e.applyThreatEnforcement(ctx, status); err != nil {
		return err
	}
	return e.ledger.Append("mhx.intelligence", "12h-sync", "verified")
}

func (e *Engine) applyThreatEnforcement(ctx context.Context, status threatintel.Status) error {
	if status.BlockingIndicators <= 0 || status.BlockingFeedsTotal <= 0 || status.BlockingFeedsReady != status.BlockingFeedsTotal || len(status.EnforcementGeneration) != 64 {
		e.setThreatEnforcementFailure(status.EnforcementGeneration, "threat intelligence enforcement snapshot is not ready")
		_ = e.ledger.Append("mhx.intelligence", "enforcement-snapshot", "rejected")
		return errors.New("threat intelligence enforcement snapshot is not ready")
	}
	e.setThreatEnforcementApplying(status)
	if err := e.acquirePolicy(ctx); err != nil {
		e.setThreatEnforcementFailure(status.EnforcementGeneration, "policy gate unavailable")
		return fmt.Errorf("threat-intelligence policy gate unavailable: %w", err)
	}
	defer e.releasePolicy()
	result, err := e.protection.ApplyThreatIntelligence(ctx, e.feeds.SnapshotPath(), status.EnforcementGeneration, status.BlockingIndicators)
	if err != nil || result.Indicators != status.BlockingIndicators || result.Generation != status.EnforcementGeneration || result.ProtectionGeneration != status.ProtectionGeneration || result.ProtectedPrefixCount != status.ProtectedPrefixes || result.Rules <= 0 || result.Shards <= 0 {
		verificationErr := err
		if verificationErr == nil {
			verificationErr = errors.New("threat intelligence firewall verification failed")
		}
		e.setThreatEnforcementFailure(status.EnforcementGeneration, "firewall enforcement verification failed")
		_ = e.ledger.Append("mhx.intelligence", "firewall-enforcement", "failed")
		return verificationErr
	}
	e.setThreatEnforcementVerified(status, result)
	return e.ledger.Append("mhx.intelligence", "firewall-enforcement", "verified-"+strings.ToLower(result.Mode))
}

func (e *Engine) setThreatEnforcementApplying(status threatintel.Status) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatEnforcement.State = "APPLYING"
	e.threatEnforcement.DesiredGeneration = status.EnforcementGeneration
	e.threatEnforcement.Error = ""
}

func (e *Engine) setThreatEnforcementFailure(desiredGeneration, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatEnforcement.State = "DEGRADED"
	e.threatEnforcement.DesiredGeneration = desiredGeneration
	e.threatEnforcement.Error = reason
}

func (e *Engine) setThreatEnforcementVerified(status threatintel.Status, result FirewallResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatEnforcement = ThreatEnforcementStatus{
		State:             "VERIFIED",
		DesiredGeneration: status.EnforcementGeneration,
		ActiveGeneration:  result.Generation,
		Indicators:        result.Indicators,
		Rules:             result.Rules,
		Shards:            result.Shards,
		Mode:              result.Mode,
		CleanupPending:    result.CleanupPending,
		VerifiedUTC:       time.Now().UTC(),
	}
	if result.CleanupPending {
		e.threatEnforcement.State = "VERIFIED_CLEANUP_PENDING"
	}
}

func (e *Engine) threatEnforcementNeedsReconcile(status threatintel.Status) bool {
	if status.BlockingIndicators <= 0 || status.BlockingFeedsReady != status.BlockingFeedsTotal || len(status.EnforcementGeneration) != 64 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.threatEnforcement.ActiveGeneration != status.EnforcementGeneration || (e.threatEnforcement.State != "VERIFIED" && e.threatEnforcement.State != "VERIFIED_CLEANUP_PENDING")
}

func (e *Engine) intelligenceLoop(stop <-chan struct{}) {
	var enforcementRetryUTC time.Time
	for {
		status := e.feeds.Status()
		now := time.Now().UTC()
		feedDue := status.NextSyncUTC.IsZero() || !now.Before(status.NextSyncUTC)
		enforcementDue := e.threatEnforcementNeedsReconcile(status) && (enforcementRetryUTC.IsZero() || !now.Before(enforcementRetryUTC))
		if feedDue || enforcementDue {
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
			var err error
			if feedDue {
				err = e.SyncFeeds(ctx)
			} else {
				err = e.applyThreatEnforcement(ctx, status)
			}
			cancel()
			if err != nil && e.threatEnforcementNeedsReconcile(e.feeds.Status()) {
				enforcementRetryUTC = time.Now().UTC().Add(threatintel.FailureRetryInterval)
			} else {
				enforcementRetryUTC = time.Time{}
			}
			continue
		}

		nextWake := status.NextSyncUTC
		if e.threatEnforcementNeedsReconcile(status) && !enforcementRetryUTC.IsZero() && (nextWake.IsZero() || enforcementRetryUTC.Before(nextWake)) {
			nextWake = enforcementRetryUTC
		}
		delay := time.Until(nextWake)
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-stop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (e *Engine) ProtectedNetworkPolicy() ProtectedNetworkPolicy {
	return e.feeds.ProtectedNetworkPolicy()
}

func (e *Engine) SetProtectedNetworkPolicy(ctx context.Context, prefixes []string) (ProtectedNetworkPolicy, error) {
	if ctx == nil {
		return ProtectedNetworkPolicy{}, errors.New("protected network policy requires context")
	}
	policy, err := e.feeds.SetProtectedPrefixes(prefixes)
	if err != nil {
		_ = e.ledger.Append("mhx.intelligence", "protected-networks", "rejected")
		return policy, err
	}
	status := e.feeds.Status()
	if status.BlockingIndicators > 0 && status.BlockingFeedsReady == status.BlockingFeedsTotal {
		if err := e.applyThreatEnforcement(ctx, status); err != nil {
			_ = e.ledger.Append("mhx.intelligence", "protected-networks", "enforcement-pending")
			return policy, err
		}
	}
	_ = e.ledger.Append("mhx.intelligence", "protected-networks", "verified")
	return policy, nil
}
