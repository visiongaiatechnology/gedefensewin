// STATUS: PLATIN
//go:build windows

package server

import (
	"os"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
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
	// The kernel-reported image path is captured and the test binary (which is
	// not the installed, signed Center/Tray product) fails closed.
	if peer.ImagePath == "" {
		t.Fatalf("peer image path missing: %+v", peer)
	}
	if executable, execErr := os.Executable(); execErr == nil && executable != "" {
		// 8.3 short-name components must be canonicalised to the long form so the
		// exact executable-name and install-tree bindings can match.
		canonicalExecutable := canonicalImagePath(executable)
		if !winapi.SameImagePath(peer.ImagePath, canonicalExecutable) {
			t.Fatalf("canonical image path mismatch: peer=%q executable=%q", peer.ImagePath, canonicalExecutable)
		}
	}
	if peer.ImageSignatureVerified && !peer.ImageTrusted {
		t.Fatalf("signature verdict without tree trust: %+v", peer)
	}
	if peer.ImageTrusted {
		// A test binary must never be considered an installed product image. If a
		// future test runner happens to execute from the install tree, the signed
		// verdict must still be independently valid.
		t.Logf("test binary resolved inside the installed tree: image=%q signed=%t", peer.ImagePath, peer.ImageSignatureVerified)
	}
	t.Logf("verified current process identity: account=%q sid=%q admin=%t operator=%t image=%q treeTrusted=%t signed=%t elevated=%t",
		peer.Account, peer.SID, peer.Administrator, peer.Operator, peer.ImagePath, peer.ImageTrusted, peer.ImageSignatureVerified, peer.Elevated)
}

// TestOperatorImageTrustFailsClosed pins the production image verdict for paths
// that cannot be the installed product: foreign or empty paths are never trusted
// and never signed (FIND-WIN-006).
func TestOperatorImageTrustFailsClosed(t *testing.T) {
	for _, imagePath := range []string{"", `C:\Users\Public\evil.exe`, `C:\Windows\System32\cmd.exe`} {
		trusted, signed := operatorImageTrust(imagePath)
		if trusted || signed {
			t.Fatalf("operatorImageTrust(%q) = trusted=%t signed=%t, want closed", imagePath, trusted, signed)
		}
	}
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

// TestCanonicalImagePath expands 8.3 short-name components when present and
// otherwise stays unchanged; unresolvable paths are returned as-is so the trust
// decision later fails closed rather than trusting a guessed path.
func TestCanonicalImagePath(t *testing.T) {
	if got := canonicalImagePath(""); got != "" {
		t.Fatalf("empty path canonicalised to %q", got)
	}
	missing := `C:\Users\Public\does-not-exist-gedefense-5.3.0.exe`
	if got := canonicalImagePath(missing); got != missing {
		t.Fatalf("unresolvable path changed: %q", got)
	}
	executable, err := os.Executable()
	if err != nil || executable == "" || !strings.Contains(executable, "~") {
		t.Skip("current executable path exposes no 8.3 short names in this environment")
	}
	canonical := canonicalImagePath(executable)
	if canonical == "" || strings.Contains(canonical, "~") {
		t.Fatalf("short executable path was not expanded: %q -> %q", executable, canonical)
	}
}
