// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("parse address %q: %v", text, err)
	}
	return address
}

func mustPrefix(t *testing.T, text string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", text, err)
	}
	return prefix
}

func TestStyxCanonicalPrefix(t *testing.T) {
	valid := []struct{ input, want string }{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3/8", "10.0.0.0/8"}, // masked, never a non-canonical prefix
		{"192.168.1.10", "192.168.1.10/32"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"::1", "::1/128"},
	}
	for _, testCase := range valid {
		prefix, err := StyxCanonicalPrefix(testCase.input)
		if err != nil {
			t.Fatalf("StyxCanonicalPrefix(%q) returned error: %v", testCase.input, err)
		}
		if prefix.String() != testCase.want {
			t.Fatalf("StyxCanonicalPrefix(%q)=%s, want %s", testCase.input, prefix, testCase.want)
		}
	}
	invalid := []string{
		"",
		" 10.0.0.0/8",
		"10.0.0.0/8 ",
		"10.0.0.0/33",
		"10.0.0.256/8",
		"2001:db8::/129",
		"::ffff:169.254.169.254/128",
		"0.0.0.0/8",
		"::/0",
		"10.0.0.0/8" + "\x00",
		"garbage",
	}
	for _, input := range invalid {
		if prefix, err := StyxCanonicalPrefix(input); err == nil {
			t.Fatalf("StyxCanonicalPrefix(%q) accepted %s but must fail closed", input, prefix)
		}
	}
}

func TestStyxCanonicalAllowPrefix(t *testing.T) {
	valid := []struct{ input, want string }{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"16.0.0.0/4", "16.0.0.0/4"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2000::/8", "2000::/8"},
	}
	for _, testCase := range valid {
		prefix, err := StyxCanonicalAllowPrefix(testCase.input)
		if err != nil {
			t.Fatalf("StyxCanonicalAllowPrefix(%q) returned error: %v", testCase.input, err)
		}
		if prefix.String() != testCase.want {
			t.Fatalf("StyxCanonicalAllowPrefix(%q)=%s, want %s", testCase.input, prefix, testCase.want)
		}
	}
	invalid := []string{
		"0.0.0.0/0",
		"::/0",
		"0.0.0.0/3",
		"0.0.0.0/4",
		"::/8",
		"2001:db8::/7",
		"0.0.0.0/8",
		"10.0.0.0/33",
	}
	for _, input := range invalid {
		if prefix, err := StyxCanonicalAllowPrefix(input); err == nil {
			t.Fatalf("StyxCanonicalAllowPrefix(%q) accepted %s but must fail closed", input, prefix)
		}
	}
}

func TestStyxMetadataVetoSeed(t *testing.T) {
	want := map[string]bool{
		"169.254.0.0/16":     false,
		"100.100.100.200/32": false,
		"168.63.129.16/32":   false,
		"192.0.0.192/32":     false,
		"fd00:ec2::254/128":  false,
		"fe80::/10":          false,
		"ff00::/8":           false,
		"0.0.0.0/8":          false,
		"224.0.0.0/4":        false,
	}
	prefixes := StyxMetadataVetoPrefixes()
	if len(prefixes) < len(want) {
		t.Fatalf("metadata veto seed has %d prefixes, want at least %d", len(prefixes), len(want))
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			t.Fatalf("metadata veto contains an invalid prefix: %v", prefix)
		}
		if _, known := want[prefix.String()]; !known {
			t.Fatalf("metadata veto seed contains unexpected prefix %s", prefix)
		}
		want[prefix.String()] = true
	}
	for prefix, found := range want {
		if !found {
			t.Fatalf("metadata veto seed is missing %s", prefix)
		}
	}
	for _, input := range []string{
		"169.254.169.254", "100.100.100.200", "168.63.129.16", "192.0.0.192",
		"fd00:ec2::254", "fe80::1", "ff02::1", "0.1.2.3", "224.0.0.1",
	} {
		if _, matched := StyxMetadataVetoMatch(mustAddr(t, input)); !matched {
			t.Fatalf("destination %s must match the mandatory metadata veto", input)
		}
	}
	// Loopback must stay usable and IPv4-mapped input must not bypass the veto.
	for _, input := range []string{"127.0.0.1", "::1", "10.0.0.1", "8.8.8.8", "2001:db8::1"} {
		if prefix, matched := StyxMetadataVetoMatch(mustAddr(t, input)); matched {
			t.Fatalf("destination %s unexpectedly matched veto %s", input, prefix)
		}
	}
	if _, matched := StyxMetadataVetoMatch(mustAddr(t, "::ffff:169.254.169.254")); !matched {
		t.Fatal("IPv4-mapped metadata address bypassed the mandatory veto")
	}
	// The accessor must hand out a copy.
	copied := StyxMetadataVetoPrefixes()
	copied[0] = netip.Prefix{}
	if !StyxMetadataVetoPrefixes()[0].IsValid() {
		t.Fatal("StyxMetadataVetoPrefixes exposed mutable global state")
	}
}

func TestStyxNormalizeDestination(t *testing.T) {
	mapped, err := StyxNormalizeDestination(mustAddr(t, "::ffff:10.0.0.1"))
	if err != nil {
		t.Fatalf("normalize mapped destination: %v", err)
	}
	if !mapped.Is4() || mapped.String() != "10.0.0.1" {
		t.Fatalf("mapped destination normalised to %s, want 10.0.0.1", mapped)
	}
	for _, input := range []string{"0.0.0.0", "::"} {
		if _, err := StyxNormalizeDestination(mustAddr(t, input)); err == nil {
			t.Fatalf("unspecified destination %s was accepted", input)
		}
	}
	if _, err := StyxNormalizeDestination(netip.Addr{}); err == nil {
		t.Fatal("zero destination was accepted")
	}
}

func TestStyxICMPv6NDExempt(t *testing.T) {
	cases := []struct {
		proto  uint8
		icmp   uint8
		exempt bool
	}{
		{styxProtoICMPv6, 135, true},
		{styxProtoICMPv6, 136, true},
		{styxProtoICMPv6, 128, false}, // echo request must not be exempt
		{styxProtoICMPv6, 134, false}, // router advertisement is not ND NS/NA
		{styxProtoTCP, 135, false},
		{0, 0, false},
	}
	for _, testCase := range cases {
		if got := StyxICMPv6NDExempt(testCase.proto, testCase.icmp); got != testCase.exempt {
			t.Fatalf("StyxICMPv6NDExempt(%d,%d)=%t, want %t", testCase.proto, testCase.icmp, got, testCase.exempt)
		}
	}
}

func TestStyxValidateBlockablePrefix(t *testing.T) {
	valid := []string{"8.8.8.8/32", "10.0.0.0/16", "2001:db8::1/128", "2001:db8::/32"}
	for _, input := range valid {
		if err := StyxValidateBlockablePrefix(mustPrefix(t, input)); err != nil {
			t.Fatalf("blockable prefix %s rejected: %v", input, err)
		}
	}
	invalid := []string{"10.0.0.0/15", "2001:db8::/31", "0.0.0.0/0", "10.1.2.3/8"}
	for _, input := range invalid {
		if err := StyxValidateBlockablePrefix(mustPrefix(t, input)); err == nil {
			t.Fatalf("blockable prefix %s accepted but violates the minimum specificity", input)
		}
	}
	if err := StyxValidateBlockablePrefix(netip.Prefix{}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
	if err := StyxValidateBlockablePrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 16)); err == nil {
		t.Fatal("unspecified prefix accepted")
	}
}

func TestStyxBlockableHostPrefix(t *testing.T) {
	v4, err := StyxBlockableHostPrefix(mustAddr(t, "8.8.4.4"))
	if err != nil || v4.String() != "8.8.4.4/32" {
		t.Fatalf("StyxBlockableHostPrefix(8.8.4.4)=%s, %v", v4, err)
	}
	v6, err := StyxBlockableHostPrefix(mustAddr(t, "2001:db8::5"))
	if err != nil || v6.String() != "2001:db8::5/128" {
		t.Fatalf("StyxBlockableHostPrefix(2001:db8::5)=%s, %v", v6, err)
	}
	mapped, err := StyxBlockableHostPrefix(mustAddr(t, "::ffff:8.8.4.4"))
	if err != nil || mapped.String() != "8.8.4.4/32" {
		t.Fatalf("mapped host prefix=%s, %v", mapped, err)
	}
	if _, err := StyxBlockableHostPrefix(netip.Addr{}); err == nil {
		t.Fatal("invalid destination produced a block prefix")
	}
}

func TestStyxEvaluatePolicyHonesty(t *testing.T) {
	off := DefaultStyxSettings()
	decision := StyxEvaluatePolicy(off, StyxPolicyRequest{Destination: mustAddr(t, "8.8.8.8"), Port: 443, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictModeOff || !decision.Allowed || decision.Enforced {
		t.Fatalf("mode=off decision = %+v, want allowed mode-off", decision)
	}

	observe := StyxSettings{Enabled: true, Mode: StyxModeObserve, Allowlist: []string{}, DNSResolvers: []string{}, Thresholds: DefaultStyxBeaconThresholds()}
	decision = StyxEvaluatePolicy(observe, StyxPolicyRequest{Destination: mustAddr(t, "8.8.8.8"), Port: 443, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictDefaultDeny || !decision.WouldBlock || !decision.Allowed || decision.Enforced {
		t.Fatalf("observe default-deny decision = %+v, want would-block but allowed", decision)
	}

	enforce := observe
	enforce.Mode = StyxModeEnforce
	decision = StyxEvaluatePolicy(enforce, StyxPolicyRequest{Destination: mustAddr(t, "8.8.8.8"), Port: 443, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictDefaultDeny || !decision.WouldBlock || decision.Allowed || !decision.Enforced {
		t.Fatalf("enforce default-deny decision = %+v, want dropped", decision)
	}
	decision = StyxEvaluatePolicy(enforce, StyxPolicyRequest{Destination: mustAddr(t, "127.0.0.1"), Port: 443, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictLoopbackExempt || !decision.Allowed {
		t.Fatalf("loopback must be exempt in enforce mode, got %+v", decision)
	}
}

func TestStyxEvaluatePolicyConflictResolution(t *testing.T) {
	// Allowlist is bypassed deliberately: the veto must win even for a revision
	// that was never accepted by validation (conflict resolution is fail-closed).
	settings := StyxSettings{
		Enabled:   true,
		Mode:      StyxModeEnforce,
		Allowlist: []string{"169.254.169.254/32", "0.0.0.0/8", "127.0.0.0/8"},
	}
	decision := StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "169.254.169.254"), Port: 80, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictMetadataVeto || decision.Allowed || !decision.Enforced {
		t.Fatalf("metadata veto lost against allowlist: %+v", decision)
	}
	// The mapped form must not bypass the veto either.
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "::ffff:100.100.100.200"), Port: 80, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictMetadataVeto || decision.Allowed {
		t.Fatalf("IPv4-mapped metadata address bypassed the veto: %+v", decision)
	}
	// Loopback stays exempt even when an allowlist rule covers it.
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "127.0.0.1"), Port: 80, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictLoopbackExempt || !decision.Allowed {
		t.Fatalf("loopback exemption lost: %+v", decision)
	}
	// ICMPv6 ND on link-local is exempt; the same prefix without ND is vetoed.
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "fe80::1"), Proto: styxProtoICMPv6, ICMPType: 135})
	if decision.Verdict != StyxVerdictNDExempt || !decision.Allowed {
		t.Fatalf("ICMPv6 ND exemption lost: %+v", decision)
	}
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "fe80::1"), Proto: styxProtoTCP, Port: 80})
	if decision.Verdict != StyxVerdictMetadataVeto || decision.Allowed {
		t.Fatalf("link-local TCP destination must be vetoed: %+v", decision)
	}
}

func TestStyxEvaluatePolicyAllowlistAndDNS(t *testing.T) {
	settings := StyxSettings{
		Enabled:      true,
		Mode:         StyxModeEnforce,
		Allowlist:    []string{"10.0.0.0/8"},
		DNSResolvers: []string{"8.8.8.0/24"},
	}
	decision := StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "10.1.2.3"), Port: 443, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictAllowlist || !decision.Allowed || decision.Enforced {
		t.Fatalf("allowlisted destination = %+v, want allowed", decision)
	}
	if decision.MatchedPrefix != "10.0.0.0/8" {
		t.Fatalf("matched prefix = %q, want 10.0.0.0/8", decision.MatchedPrefix)
	}
	// DNS pin: only configured resolvers may receive port 53/853.
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "8.8.8.8"), Port: 53, Proto: styxProtoUDP})
	if decision.Verdict != StyxVerdictDNSResolver || !decision.Allowed {
		t.Fatalf("configured resolver was not permitted: %+v", decision)
	}
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "1.1.1.1"), Port: 853, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictDNSVeto || decision.Allowed || !decision.Enforced {
		t.Fatalf("unconfigured DNS resolver was not vetoed: %+v", decision)
	}
	// The DNS pin only covers transport ports; 443 traffic is default-deny.
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "1.1.1.1"), Port: 443, Proto: styxProtoTCP})
	if decision.Verdict != StyxVerdictDefaultDeny || decision.Allowed {
		t.Fatalf("non-DNS traffic to an unlisted peer = %+v, want default-deny", decision)
	}
	// DNS pinning must not exempt an allowlisted destination on port 53 either.
	decision = StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: mustAddr(t, "10.9.9.9"), Port: 53, Proto: styxProtoUDP})
	if decision.Verdict != StyxVerdictDNSVeto || decision.Allowed {
		t.Fatalf("DNS pin did not win over allowlist: %+v", decision)
	}
}

func TestStyxEvaluatePolicyInvalidDestination(t *testing.T) {
	settings := StyxSettings{Enabled: true, Mode: StyxModeEnforce}
	decision := StyxEvaluatePolicy(settings, StyxPolicyRequest{Destination: netip.Addr{}})
	if decision.Verdict != StyxVerdictInvalidTarget || decision.Allowed || !decision.WouldBlock {
		t.Fatalf("invalid destination decision = %+v, want fail-closed", decision)
	}
	observe := settings
	observe.Mode = StyxModeObserve
	decision = StyxEvaluatePolicy(observe, StyxPolicyRequest{Destination: netip.Addr{}})
	if decision.Verdict != StyxVerdictInvalidTarget || !decision.Allowed || !decision.WouldBlock {
		t.Fatalf("invalid destination in observe mode = %+v", decision)
	}
}

func TestStyxPrefixesOverlap(t *testing.T) {
	cases := []struct {
		left, right string
		overlap     bool
	}{
		{"10.0.0.0/8", "10.1.0.0/16", true},
		{"10.0.0.0/8", "11.0.0.0/8", false},
		{"2001:db8::/32", "2001:db8:1::/48", true},
		{"2001:db8::/32", "2001:db9::/32", false},
		{"0.0.0.0/8", "0.0.0.0/8", true},
	}
	for _, testCase := range cases {
		if got := styxPrefixesOverlap(mustPrefix(t, testCase.left), mustPrefix(t, testCase.right)); got != testCase.overlap {
			t.Fatalf("styxPrefixesOverlap(%s,%s)=%t, want %t", testCase.left, testCase.right, got, testCase.overlap)
		}
	}
	if styxPrefixesOverlap(netip.Prefix{}, netip.Prefix{}) {
		t.Fatal("invalid prefixes reported an overlap")
	}
}
