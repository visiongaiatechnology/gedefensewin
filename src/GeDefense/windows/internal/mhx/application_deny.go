package mhx

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// applicationDenyController is optional so the many existing test doubles for
// the established protectionController do not need to grow a stub for a
// capability they do not exercise. The production protectionManager implements
// it.
type applicationDenyController interface {
	ApplicationDenies(context.Context, string, string) (ApplicationDenyResult, error)
}

// ApplicationDenies lists the operator-selected application network-deny
// rules. The list is backed by the signed Set-VgtMhxApplicationDeny.ps1
// transaction and therefore reflects real Windows Firewall rules, not a Go
// preference list.
func (e *Engine) ApplicationDenies(ctx context.Context) ([]ApplicationDeny, error) {
	if e == nil {
		return nil, errors.New("MHX application-deny controller unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("application-deny query requires an active request")
	}
	if err := e.acquirePolicy(ctx); err != nil {
		return nil, err
	}
	defer e.releasePolicy()
	controller, ok := e.protection.(applicationDenyController)
	if !ok {
		return nil, errors.New("application-deny controller unsupported by this protection engine")
	}
	result, err := controller.ApplicationDenies(ctx, "List", "")
	if err != nil {
		return nil, fmt.Errorf("application-deny inventory unavailable: %w", err)
	}
	return result.Entries, nil
}

// SetApplicationDeny adds or removes one program from the real Windows
// Firewall deny group. Removal is explicit; adding an unchanged entry is
// idempotent. The script validates the executable path, hash and rule group.
func (e *Engine) SetApplicationDeny(ctx context.Context, action, path string) ([]ApplicationDeny, error) {
	if e == nil {
		return nil, errors.New("MHX application-deny controller unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("application-deny update requires an active request")
	}
	action = strings.TrimSpace(action)
	if action != "Add" && action != "Remove" {
		return nil, errors.New("application-deny action rejected")
	}
	path = strings.TrimSpace(path)
	if err := validateWindowsExecutablePath(path); err != nil {
		return nil, err
	}
	if err := e.acquirePolicy(ctx); err != nil {
		return nil, err
	}
	defer e.releasePolicy()
	controller, ok := e.protection.(applicationDenyController)
	if !ok {
		return nil, errors.New("application-deny controller unsupported by this protection engine")
	}
	result, err := controller.ApplicationDenies(ctx, action, path)
	if err != nil {
		_ = e.ledger.Append("mhx.application-deny", strings.ToLower(action), "failed")
		return nil, fmt.Errorf("application-deny transaction rejected: %w", err)
	}
	resultAction := strings.ToLower(action)
	if err := e.ledger.Append("mhx.application-deny", resultAction, fmt.Sprintf("verified; count=%d", result.Count)); err != nil {
		return nil, err
	}
	return result.Entries, nil
}
