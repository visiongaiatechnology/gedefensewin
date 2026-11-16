// STATUS: PLATIN VGT SUPREME
package threatintel

// FIND-WIN-015 regression tests for the network self-protection layer.
//
// The package TestMain pins the host-resolver veto provider to a deterministic
// empty set so enforcement-compiler expectations never depend on the DNS
// configuration of the machine running the tests. Tests that exercise the
// resolver veto install their own deterministic provider.

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	previous := resolverAddressProvider
	resolverAddressProvider = func() []netip.Addr { return nil }
	code := m.Run()
	resolverAddressProvider = previous
	os.Exit(code)
}

func withResolverAddresses(t *testing.T, addresses ...string) {
	t.Helper()
	parsed := make([]netip.Addr, 0, len(addresses))
	for _, value := range addresses {
		address, err := netip.ParseAddr(value)
		if err != nil {
			t.Fatalf("invalid test resolver address %q: %v", value, err)
		}
		parsed = append(parsed, address)
	}
	previous := resolverAddressProvider
	resolverAddressProvider = func() []netip.Addr { return parsed }
	t.Cleanup(func() { resolverAddressProvider = previous })
}

func TestThreatPrefixRejectsSelfLockoutWidths(t *testing.T) {
	for _, value := range []string{"8.0.0.0/8", "0.0.0.0/0", "1.0.0.0/9", "2606:4700::/31"} {
		if _, err := parseThreatToken(value); err == nil {
			t.Fatalf("self-lockout width prefix accepted: %s", value)
		}
	}
	if _, err := parseThreatToken("8.0.0.0/16"); err != nil {
		t.Fatalf("documented /16 IPv4 floor rejected: %v", err)
	}
	if _, err := parseThreatToken("2606:4700::/32"); err != nil {
		t.Fatalf("documented /32 IPv6 floor rejected: %v", err)
	}
}

func TestThreatPrefixRejectsHostControlPlaneTargets(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1", "127.0.0.0/8", "::1", "fe80::1",
		"169.254.169.254", "169.254.0.0/16", "169.254.170.2",
		"100.100.100.200", "fd00:ec2::254", "255.255.255.255",
	} {
		if _, err := parseThreatToken(value); err == nil {
			t.Fatalf("self-protection target accepted as a threat indicator: %s", value)
		}
	}
}

func TestEnforcementCompilerRejectsBroadSelfLockoutPrefix(t *testing.T) {
	for _, value := range []string{"8.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8"} {
		if _, err := compileEnforcementIndicators([]string{value}, nil); err == nil {
			t.Fatalf("broad/self-protection prefix compiled into enforcement: %s", value)
		}
	}
}

func TestEnforcementCompilerVetoesConfiguredResolverInsideBlock(t *testing.T) {
	withResolverAddresses(t, "8.8.8.8")
	compiled, err := compileEnforcementIndicators([]string{"8.8.0.0/16"}, nil)
	if err != nil {
		t.Fatalf("compile with resolver veto: %v", err)
	}
	if len(compiled) == 0 {
		t.Fatal("resolver veto removed the whole block instead of carving the resolver")
	}
	resolver := netip.MustParseAddr("8.8.8.8")
	for _, value := range compiled {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("invalid compiled prefix %q: %v", value, err)
		}
		if prefix.Contains(resolver) {
			t.Fatalf("configured host resolver leaked into enforcement: %s (all=%v)", value, compiled)
		}
	}
	// The rest of the block must stay enforceable.
	stillBlocked := false
	for _, value := range compiled {
		if netip.MustParsePrefix(value).Contains(netip.MustParseAddr("8.8.9.9")) {
			stillBlocked = true
		}
	}
	if !stillBlocked {
		t.Fatalf("resolver veto removed unrelated addresses from the block: %v", compiled)
	}
}

func TestEnforcementCompilerVetoesCloudMetadataTargets(t *testing.T) {
	// IMDS/link-local prefixes are rejected at validation, and the compiler
	// additionally subtracts the immutable veto set from accepted blocks.
	if _, err := compileEnforcementIndicators([]string{"169.254.169.254/32"}, nil); err == nil {
		t.Fatal("IMDS target compiled into enforcement")
	}
	if _, err := compileEnforcementIndicators([]string{"8.8.8.0/24"}, nil); err != nil {
		t.Fatalf("ordinary block rejected: %v", err)
	}
}

func TestSelfProtectionVetoIncludesStaticRanges(t *testing.T) {
	withResolverAddresses(t, "9.9.9.9")
	veto := selfProtectionVetoPrefixes()
	foundResolver := false
	for _, prefix := range veto {
		if prefix.Addr().String() == "9.9.9.9" && prefix.Bits() == 32 {
			foundResolver = true
		}
	}
	if !foundResolver {
		t.Fatalf("configured resolver missing from the veto set: %v", veto)
	}
	for _, required := range []string{"127.0.0.0/8", "169.254.0.0/16", "fd00:ec2::254/128"} {
		found := false
		for _, prefix := range veto {
			if prefix.String() == required {
				found = true
			}
		}
		if !found {
			t.Fatalf("static self-protection range %s missing from the veto set", required)
		}
	}
}

func TestResolverVetoProviderFailureDegradesToStaticSetOnly(t *testing.T) {
	withResolverAddresses(t, "8.8.8.8")
	withResolverAddresses(t) // override again with an empty set
	veto := selfProtectionVetoPrefixes()
	for _, prefix := range veto {
		if strings.HasPrefix(prefix.String(), "8.8.8.8") {
			t.Fatalf("empty resolver provider still vetoes an address: %v", veto)
		}
	}
	if _, err := compileEnforcementIndicators([]string{"8.8.0.0/16"}, nil); err != nil {
		t.Fatalf("compile without resolver veto failed: %v", err)
	}
}

// The Windows resolver query must never panic and must stay bounded even if the
// platform returns an unexpected layout; the production provider is exercised
// here for its bounded, non-failing contract only.
func TestPlatformResolverAddressesAreBounded(t *testing.T) {
	addresses := platformResolverAddresses()
	if len(addresses) > maximumResolverVetoAddresses {
		t.Fatalf("resolver list exceeds the veto boundary: %d", len(addresses))
	}
	for _, address := range addresses {
		if !address.IsValid() || !address.Is4() {
			t.Fatalf("platform resolver address rejected internal contract: %v", address)
		}
	}
}
