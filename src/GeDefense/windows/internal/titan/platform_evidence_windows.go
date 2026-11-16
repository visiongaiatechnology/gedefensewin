// STATUS: PLATIN VGT SUPREME
//go:build windows

package titan

import "github.com/visiongaiatechnology/gedefense/windows/internal/winapi"

// Bind the platform-specific Authenticode verifier. Every non-zero result is a
// failure; the generic default stays fail-closed on non-Windows builds.
func init() {
	titanVerifyAuthenticode = winapi.VerifyAuthenticode
}
