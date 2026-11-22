// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package mhx

import (
	"context"
	"errors"
)

func locateDefenderCLI() (string, error) {
	return "", errors.New("MpCmdRun.exe is only available on Windows")
}

func runDefenderFileOracle(context.Context, string) (DefenderScanResult, error) {
	return DefenderScanResult{}, errors.New("MpCmdRun.exe is only available on Windows")
}
