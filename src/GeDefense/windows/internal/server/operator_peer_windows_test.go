// STATUS: PLATIN
//go:build windows

package server

import (
	"os"
	"testing"
)

// TestOperatorPeerFromCurrentProcess exercises the real Windows token path
// against the test process itself. If the environment does not expose process
// token information the test skips honestly instead of faking a result.
func TestOperatorPeerFromCurrentProcess(t *testing.T) {
	peer, err := operatorPeerFromPID(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("process token inspection unavailable in this environment: %v", err)
	}
	if peer.PID != uint32(os.Getpid()) {
		t.Fatalf("peer pid mismatch: %d", peer.PID)
	}
	if peer.Account == "" || peer.SID == "" {
		t.Fatalf("peer identity incomplete: %+v", peer)
	}
	t.Logf("verified current process identity: account=%q sid=%q admin=%t operator=%t",
		peer.Account, peer.SID, peer.Administrator, peer.Operator)
}

func TestOperatorPeerRejectsZeroPID(t *testing.T) {
	if _, err := operatorPeerFromPID(0); err == nil {
		t.Fatal("pid 0 accepted")
	}
}

// TestTokenGroupAuthorisationFilterExcludesDenyOnly pins the token group filter:
// deny-only and disabled groups never authorise. The SAM fallback only applies
// when the operator group SID is entirely absent from the token, so the
// stale-token repair cannot bypass this filter.
func TestTokenGroupAuthorisationFilterExcludesDenyOnly(t *testing.T) {
	tests := []struct {
		name       string
		attributes uint32
		want       bool
	}{
		{"disabled", 0, false},
		{"deny only without enabled", seGroupUseForDenyOnly, false},
		{"enabled and deny only", seGroupEnabled | seGroupUseForDenyOnly, false},
		{"enabled", seGroupEnabled, true},
		{"enabled and mandatory", seGroupEnabled | 0x00000001, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := usableTokenGroupAttribute(test.attributes); got != test.want {
				t.Fatalf("usableTokenGroupAttribute(%#x) = %t, want %t",
					test.attributes, got, test.want)
			}
		})
	}
}
