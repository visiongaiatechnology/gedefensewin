// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package mhx

import "errors"

func isTelemetryProcess(imagePath string) bool {
	return false
}

func applyGhostModeHostsSinkhole(enable bool) error {
	return errors.New("ghost mode requires Windows")
}
