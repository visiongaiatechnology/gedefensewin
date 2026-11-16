// STATUS: DIAMANT VGT SUPREME
//go:build !windows

// Package parsercells is a Windows-only isolation package. The Windows
// implementation uses AppContainer profiles (userenv.dll), Job Objects and
// CreateProcess attribute mitigations (kernel32.dll) and therefore cannot exist
// on other operating systems. This stub keeps the package importable on other
// platforms and fails closed instead of pretending support.
package parsercells

import "errors"

// ErrUnsupportedPlatform is returned by every unsupported-platform entry point.
var ErrUnsupportedPlatform = errors.New("parsercells: package requires Windows (AppContainer + Job Objects)")

// Supported reports whether the running platform implements parser cells.
func Supported() bool { return false }

// Unsupported returns ErrUnsupportedPlatform; it is the single entry point of
// the non-Windows stub.
func Unsupported() error { return ErrUnsupportedPlatform }
