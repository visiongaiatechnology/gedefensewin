package mhx

import (
	"context"
	"errors"
)

// SetKineticArmed authorizes burst+Threat-IP correlation only.
// The actual firewall enforcement still belongs to the existing verified
// WFP threat-intelligence generation. No separate dynamic rule is installed.
func (e *Engine) SetKineticArmed(ctx context.Context, armed bool) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("kinetic control requires an active request")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if armed {
		if !e.wfpRealtime || !e.networkRealtime {
			return errors.New("kinetic: required Windows telemetry unavailable")
		}
		te := e.threatEnforcement
		feed := e.feeds.Status()
		if (te.State != "VERIFIED" && te.State != "VERIFIED_CLEANUP_PENDING") || te.ActiveGeneration == "" || te.ActiveGeneration != feed.EnforcementGeneration || feed.BlockingIndicators == 0 {
			return errors.New("kinetic: verified Threat-IP WFP generation required")
		}
	}
	if armed {
		if err := e.ledger.Append("kinetic.mode", "threat-ip-correlation", "ARMED"); err != nil {
			return err
		}
	}
	if !armed {
		if err := e.ledger.Append("kinetic.mode", "threat-ip-correlation", "DISARMED"); err != nil {
			return err
		}
	}
	e.kineticArmed = armed
	return nil
}
