// STATUS: PLATIN VGT SUPREME
//go:build !windows

package mhx

import (
	"context"
	"errors"
	"net/netip"
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

type unsupportedStyxEnforcer struct{}

func newStyxEnforcer() styxEnforcer {
	return unsupportedStyxEnforcer{}
}

func (unsupportedStyxEnforcer) Sync(context.Context, styxEnforceConfig) (styxEnforceState, error) {
	msg := "Windows Filtering Platform enforcement is only available on Windows"
	return styxEnforceState{LastError: msg}, errors.New(msg)
}

func (unsupportedStyxEnforcer) Close() error { return nil }

func (unsupportedStyxEnforcer) State() styxEnforceState { return styxEnforceState{} }
