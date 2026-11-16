// STATUS: PLATIN VGT SUPREME
package titan

import (
	"errors"
	"testing"
)

// withTitanSignatureVerifier injects a deterministic Authenticode verifier for
// tolerance tests. The bounded probe cache is reset before and after the test so
// no verification result leaks between fixtures.
func withTitanSignatureVerifier(t *testing.T, verify func(string) error) {
	t.Helper()
	previous := titanVerifyAuthenticode
	resetTitanSignatureProbes()
	titanVerifyAuthenticode = verify
	t.Cleanup(func() {
		titanVerifyAuthenticode = previous
		resetTitanSignatureProbes()
	})
}

// alwaysValidSignatureVerifier accepts every path. Tests that use it isolate the
// canonical paths they assert on through fixtures; it never stands in for a real
// signature check outside the test binary.
func alwaysValidSignatureVerifier(string) error { return nil }

var errUnsignedInTest = errors.New("test fixture: path is not Authenticode signed")
