// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package userlaunch

import "errors"

var errUnsupported = errors.New("userlaunch: shell-user relaunch is only supported on Windows")

// IsElevated reports false on non-Windows platforms; the GeDefense UI is a
// Windows product, but the package must stay buildable for documentation tools.
func IsElevated() bool { return false }

// CommandLine is unavailable without the Windows command-line rules.
func CommandLine(string, []string) (string, error) { return "", errUnsupported }

// LaunchAsShellUser is unavailable without the Windows desktop shell token.
func LaunchAsShellUser(string, []string) error { return errUnsupported }

// RelaunchUnelevatedIfNeeded is unavailable without the Windows desktop shell.
func RelaunchUnelevatedIfNeeded(string, []string) (bool, error) { return false, errUnsupported }
