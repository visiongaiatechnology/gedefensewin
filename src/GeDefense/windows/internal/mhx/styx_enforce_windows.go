// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"net/netip"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

type styxEnforceConfig struct {
	BlockPrefixes  []netip.Prefix
	PermitAppPaths []string
}

type styxEnforceState struct {
	Active      bool
	FilterCount int
	LastError   string
}

type styxEnforcer interface {
	Sync(ctx context.Context, cfg styxEnforceConfig) (styxEnforceState, error)
	Close() error
	State() styxEnforceState
}

type winapiStyxEnforcer struct {
	engine *winapi.WFPEngine
}

func newStyxEnforcer() styxEnforcer {
	return &winapiStyxEnforcer{engine: winapi.NewWFPEngine()}
}

func (e *winapiStyxEnforcer) Sync(ctx context.Context, cfg styxEnforceConfig) (styxEnforceState, error) {
	status, err := e.engine.SyncPolicy(ctx, winapi.WFPConfig{
		DryRun:             false,
		BlockMetadata:      true,
		PermitAppPaths:     cfg.PermitAppPaths,
		ExtraBlockPrefixes: cfg.BlockPrefixes,
	})
	return styxEnforceState{
		Active:      status.Active,
		FilterCount: len(status.FilterIDs),
		LastError:   status.LastError,
	}, err
}

func (e *winapiStyxEnforcer) Close() error {
	return e.engine.Close()
}

func (e *winapiStyxEnforcer) State() styxEnforceState {
	status := e.engine.Status()
	return styxEnforceState{
		Active:      status.Active,
		FilterCount: len(status.FilterIDs),
		LastError:   status.LastError,
	}
}
