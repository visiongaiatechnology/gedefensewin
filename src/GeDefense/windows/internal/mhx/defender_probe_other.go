// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package mhx

import (
	"context"
	"errors"
)

// probeDefenderTelemetry is unavailable outside Windows; the engine reports an
// explicit unavailable snapshot instead of inventing Defender values.
func probeDefenderTelemetry(context.Context) (DefenderTelemetry, error) {
	return DefenderTelemetry{}, errors.New("defender telemetry requires Windows")
}
