// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (e *Engine) Mode() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.mode }

func (e *Engine) SetMode(parent context.Context, mode string) error {
	if mode != "monitor" && mode != "guarded" && mode != "sovereign" {
		return errors.New("unsupported MHX protection mode")
	}
	if parent == nil {
		return errors.New("MHX mode transition requires context")
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	if err := e.acquirePolicy(ctx); err != nil {
		return fmt.Errorf("MHX policy gate unavailable: %w", err)
	}
	defer e.releasePolicy()

	if err := e.ledger.Verify(); err != nil {
		e.setProtectionHealth("DEGRADED")
		return fmt.Errorf("evidence ledger verification failed: %w", err)
	}
	previous := e.Mode()
	if mode == previous {
		return nil
	}

	if err := e.applyVerifiedMode(ctx, mode); err != nil {
		rollbackErr := e.rollbackMode(previous)
		if rollbackErr != nil {
			e.setProtectionHealth("DEGRADED")
			_ = e.ledger.Append("mhx.mode", "protection-mode", "transition-failed-rollback-failed")
			return fmt.Errorf("MHX mode transition failed: %w; rollback failed: %v", err, rollbackErr)
		}
		e.setProtectionHealth("VERIFIED")
		_ = e.ledger.Append("mhx.mode", "protection-mode", "transition-failed-rolled-back")
		return err
	}

	if err := e.persistMode(mode); err != nil {
		rollbackErr := e.rollbackMode(previous)
		if rollbackErr != nil {
			e.setProtectionHealth("DEGRADED")
			_ = e.ledger.Append("mhx.mode", "protection-mode", "persist-failed-rollback-failed")
			return fmt.Errorf("MHX mode persistence failed: %w; rollback failed: %v", err, rollbackErr)
		}
		e.setProtectionHealth("VERIFIED")
		_ = e.ledger.Append("mhx.mode", "protection-mode", "persist-failed-rolled-back")
		return err
	}

	if err := e.ledger.Append("mhx.mode", "protection-mode", mode); err != nil {
		rollbackErr := e.rollbackMode(previous)
		if rollbackErr != nil {
			e.setProtectionHealth("DEGRADED")
			return fmt.Errorf("evidence commit failed: %w; rollback failed: %v", err, rollbackErr)
		}
		e.setProtectionHealth("VERIFIED")
		return fmt.Errorf("evidence commit failed; protection rolled back: %w", err)
	}

	e.mu.Lock()
	e.mode = mode
	e.mu.Unlock()
	e.refreshKernelEnforcement(ctx)
	e.setProtectionHealth("VERIFIED")
	return nil
}

func (e *Engine) persistMode(mode string) error {
	payload, err := json.Marshal(struct {
		Mode       string    `json:"mode"`
		UpdatedUTC time.Time `json:"updatedUtc"`
	}{mode, time.Now().UTC()})
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(e.root, "mode.json"), append(payload, '\n'))
}

func (e *Engine) rollbackMode(previous string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var rollbackErrors []error
	if err := e.applyVerifiedMode(ctx, previous); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("protection rollback: %w", err))
	}
	if err := e.persistMode(previous); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("mode-state rollback: %w", err))
	}
	e.refreshKernelEnforcement(ctx)
	return errors.Join(rollbackErrors...)
}

func (e *Engine) applyVerifiedMode(ctx context.Context, mode string) error {
	if mode == "sovereign" {
		appControl, err := e.protection.ApplyAppControl(ctx, "Enforce")
		if err != nil {
			return err
		}
		if !appControl.Enforced || !appControl.KernelEnforcement {
			return errors.New("App Control kernel enforcement verification failed")
		}
		e.kernelEnforcement.Store(appControl.KernelEnforcement)
	}

	verified, err := e.protection.Apply(ctx, mode)
	if err != nil {
		return err
	}
	if verified.Mode != mode || !verified.DefenderRealtime || !verified.ProcessTelemetry || (mode == "sovereign" && !verified.NetworkDefaultDeny) {
		return errors.New("MHX protection verification failed")
	}

	if mode != "sovereign" {
		appControl, err := e.protection.ApplyAppControl(ctx, "Audit")
		if err != nil {
			return err
		}
		if appControl.Enforced || appControl.KernelEnforcement {
			return errors.New("App Control audit verification failed")
		}
		e.kernelEnforcement.Store(false)
	}
	return nil
}

func (e *Engine) refreshKernelEnforcement(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	result, err := e.protection.ApplyAppControl(ctx, "Status")
	if err != nil {
		_ = e.ledger.Append("mhx.appcontrol", "status", "unavailable")
		return
	}
	e.kernelEnforcement.Store(result.KernelEnforcement)
}

func (e *Engine) acquirePolicy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("policy operation requires context")
	}
	e.policyOnce.Do(func() { e.policyGate = make(chan struct{}, 1) })
	select {
	case e.policyGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) releasePolicy() {
	<-e.policyGate
}

func (e *Engine) setProtectionHealth(state string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.protectionHealth = state
	if state == "VERIFIED" {
		e.protectionVerifiedUTC = time.Now().UTC()
		return
	}
	e.protectionVerifiedUTC = time.Time{}
}

func (e *Engine) loadMode() error {
	payload, err := os.ReadFile(filepath.Join(e.root, "mode.json"))
	if err != nil {
		return err
	}
	var state struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return err
	}
	if state.Mode != "monitor" && state.Mode != "guarded" && state.Mode != "sovereign" {
		return errors.New("persisted MHX mode is invalid")
	}
	e.mode = state.Mode
	return nil
}

func (e *Engine) Applications(ctx context.Context) ([]ApplicationAllow, error) {
	if err := e.acquirePolicy(ctx); err != nil {
		return nil, err
	}
	defer e.releasePolicy()
	result, err := e.protection.Applications(ctx, "List", "")
	return result.Entries, err
}

func (e *Engine) SetApplication(ctx context.Context, action, path string) ([]ApplicationAllow, error) {
	if action != "Add" && action != "Remove" {
		return nil, errors.New("application allow action rejected")
	}
	if err := e.acquirePolicy(ctx); err != nil {
		return nil, err
	}
	defer e.releasePolicy()
	result, err := e.protection.Applications(ctx, action, path)
	if err != nil {
		_ = e.ledger.Append("mhx.sovereign", "application-allow", "failed")
		return nil, err
	}
	appAction := "Audit"
	if e.Mode() == "sovereign" {
		appAction = "Enforce"
	}
	appControl, appErr := e.protection.ApplyAppControl(ctx, appAction)
	if appErr != nil {
		e.setProtectionHealth("DEGRADED")
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "failed")
		return nil, appErr
	}
	if appAction == "Enforce" && (!appControl.Enforced || !appControl.KernelEnforcement) {
		e.setProtectionHealth("DEGRADED")
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "verification-failed")
		return nil, errors.New("App Control kernel enforcement verification failed")
	}
	if appAction == "Audit" && (appControl.Enforced || appControl.KernelEnforcement) {
		e.setProtectionHealth("DEGRADED")
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "verification-failed")
		return nil, errors.New("App Control audit verification failed")
	}
	e.kernelEnforcement.Store(appControl.KernelEnforcement)
	_ = e.ledger.Append("mhx.sovereign", "application-allow", strings.ToLower(action))
	return result.Entries, nil
}

func (e *Engine) allowVerificationLoop(stop <-chan struct{}) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			if err := e.acquirePolicy(ctx); err == nil {
				_, verifyErr := e.protection.Applications(ctx, "Verify", "")
				e.releasePolicy()
				if verifyErr != nil {
					if e.Mode() == "sovereign" {
						e.setProtectionHealth("DEGRADED")
					}
					_ = e.ledger.Append("mhx.sovereign", "application-integrity", "failed")
				}
			} else if e.Mode() == "sovereign" {
				e.setProtectionHealth("DEGRADED")
				_ = e.ledger.Append("mhx.sovereign", "application-integrity", "policy-gate-unavailable")
			}
			cancel()
			timer.Reset(time.Minute)
		}
	}
}

func (e *Engine) policyReconciliationLoop(stop <-chan struct{}) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			if err := e.acquirePolicy(ctx); err != nil {
				e.setProtectionHealth("DEGRADED")
				_ = e.ledger.Append("mhx.enforcement", "policy-gate", "degraded")
			} else {
				err = e.applyVerifiedMode(ctx, e.Mode())
				e.releasePolicy()
				if err != nil {
					e.setProtectionHealth("DEGRADED")
					_ = e.ledger.Append("mhx.enforcement", "policy-reconciliation", "degraded")
				} else {
					e.setProtectionHealth("VERIFIED")
				}
			}
			cancel()
			timer.Reset(10 * time.Minute)
		}
	}
}
