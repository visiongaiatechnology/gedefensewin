// STATUS: PLATIN VGT SUPREME
package mhx

// Windows V6 Phase 1: the pure StyX policy layer.
//
// This file is the 1:1 port of the Linux V6 policy core: the canonical CIDR
// validation of control/coreipc.go (styxCanonicalCIDR), the mandatory
// metadata/link-local/multicast veto seed and the ordered veto/allow
// resolution of docs/POINT3-EGRESS-BEACON.md §6. Everything here is a pure
// function of its inputs: no socket, no registry, no global mutable state.
//
// Windows has no cgroups, so the operator allowlist is host wide; the veto set
// is hard-wired and cannot be disabled by settings ("Metadata-/DNS-Veto
// automatisch"). Loopback and ICMPv6 neighbour discovery (NS/NA on link-local)
// are exempt from the veto, exactly like Linux (§6.7, §13.7).

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// styxMaxCIDRTextBytes bounds one CIDR token before parsing.
	styxMaxCIDRTextBytes = 128

	// StyxMinBlockPrefixBitsV4/V6 is the most coarse block rule StyX may ever
	// derive: never block more than a /16 IPv4 or a /32 IPv6 range.
	StyxMinBlockPrefixBitsV4 = 16
	StyxMinBlockPrefixBitsV6 = 32

	// styxMinAllowPrefixBitsV4/V6 reject allow-all style rules (§13.2): an
	// allowlist entry broader than /4 (IPv4) or /8 (IPv6) is refused. Allow-all
	// is expressed exclusively through mode=off, never through a CIDR.
	styxMinAllowPrefixBitsV4 = 4
	styxMinAllowPrefixBitsV6 = 8

	// StyXDNSPlainPort / StyXDNSDoTLSPort are the transport ports covered by the
	// DNS pin rule (§6.8).
	StyXDNSPlainPort = 53
	StyXDNSDoTLSPort = 853

	// styxProtoICMPv6 and the neighbour-discovery types are the documented
	// ICMPv6 ND exemption (§6.7, §13.7).
	styxProtoICMPv6                 = 58
	styxNDTypeNeighborSolicitation  = 135
	styxNDTypeNeighborAdvertisement = 136
)

// styxMetadataVetoPrefixes is the mandatory veto seed from
// docs/POINT3-EGRESS-BEACON.md §4 ("Pflicht-Veto"). It is an array, not a
// slice, so package code cannot append to or reslice it; the accessor hands out
// a copy. 127.0.0.0/8 and ::1 are deliberately absent: loopback must keep
// working.
var styxMetadataVetoPrefixes = [...]netip.Prefix{
	styxVetoV4(169, 254, 0, 0, 16),                                        // AWS/Azure/GCP/Oracle IMDS
	styxVetoV4(100, 100, 100, 200, 32),                                    // Alibaba Cloud metadata
	styxVetoV4(168, 63, 129, 16, 32),                                      // Azure wireserver
	styxVetoV4(192, 0, 0, 192, 32),                                        // Oracle Cloud metadata
	styxVetoV6(128, [4]byte{0xfd, 0x00, 0x0e, 0xc2}, [2]byte{0x02, 0x54}), // fd00:ec2::254
	styxVetoV6(10, [4]byte{0xfe, 0x80, 0x00, 0x00}, [2]byte{}),            // fe80::/10 link-local
	styxVetoV6(8, [4]byte{0xff, 0x00, 0x00, 0x00}, [2]byte{}),             // ff00::/8 multicast
	styxVetoV4(0, 0, 0, 0, 8),                                             // 0.0.0.0/8 "this network"
	styxVetoV4(224, 0, 0, 0, 4),                                           // 224.0.0.0/4 IPv4 multicast
}

func styxVetoV4(a, b, c, d byte, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits)
}

func styxVetoV6(bits int, head [4]byte, tail [2]byte) netip.Prefix {
	var octets [16]byte
	copy(octets[:4], head[:])
	copy(octets[14:], tail[:])
	return netip.PrefixFrom(netip.AddrFrom16(octets), bits)
}

// StyxMetadataVetoPrefixes returns a copy of the mandatory veto set. The copy
// is safe to keep; mutating it does not change policy.
func StyxMetadataVetoPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(styxMetadataVetoPrefixes))
	copy(prefixes, styxMetadataVetoPrefixes[:])
	return prefixes
}

// StyxCanonicalPrefix validates and canonicalises one CIDR token. It accepts a
// bare address (host prefix) or an ip/len token, rejects whitespace/NUL and
// over-long tokens, rejects IPv4-mapped IPv6 input (which would be an easy
// ::ffff: bypass) and returns the masked prefix with a defined network address.
func StyxCanonicalPrefix(raw string) (netip.Prefix, error) {
	if raw == "" {
		return netip.Prefix{}, errors.New("styX CIDR is empty")
	}
	if len(raw) > styxMaxCIDRTextBytes {
		return netip.Prefix{}, errors.New("styX CIDR exceeds the boundary")
	}
	if strings.ContainsAny(raw, " \t\r\n\x00") {
		return netip.Prefix{}, fmt.Errorf("styX CIDR %q contains rejected characters", raw)
	}
	var (
		address netip.Addr
		bits    int
	)
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("styX CIDR %q is not a valid prefix: %w", raw, err)
		}
		address, bits = prefix.Addr(), prefix.Bits()
	} else {
		parsed, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("styX CIDR %q is not a valid address: %w", raw, err)
		}
		address, bits = parsed, parsed.BitLen()
	}
	if address.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("styX CIDR %q must not be an IPv4-mapped IPv6 address", raw)
	}
	address = address.Unmap()
	if !address.IsValid() || (!address.Is4() && !address.Is6()) {
		return netip.Prefix{}, fmt.Errorf("styX CIDR %q is not a usable unicast family", raw)
	}
	if address.IsUnspecified() {
		return netip.Prefix{}, fmt.Errorf("styX CIDR %q is the unspecified address", raw)
	}
	prefix := netip.PrefixFrom(address, bits)
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("styX CIDR %q has an out-of-range prefix length", raw)
	}
	return prefix.Masked(), nil
}

// StyxCanonicalAllowPrefix canonicalises one allowlist entry and enforces the
// documented allow-all boundary: an allow rule broader than /4 (IPv4) or /8
// (IPv6) is refused; 0.0.0.0/0 and ::/0 are never expressible.
func StyxCanonicalAllowPrefix(raw string) (netip.Prefix, error) {
	prefix, err := StyxCanonicalPrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("styX allowlist rejects %q: allow-all must be expressed as mode=off, never as a /0 CIDR", raw)
	}
	if prefix.Addr().Is4() {
		if prefix.Bits() < styxMinAllowPrefixBitsV4 {
			return netip.Prefix{}, fmt.Errorf("styX allowlist rejects %s: IPv4 allow rules must be /%d or narrower", prefix, styxMinAllowPrefixBitsV4)
		}
		return prefix, nil
	}
	if prefix.Bits() < styxMinAllowPrefixBitsV6 {
		return netip.Prefix{}, fmt.Errorf("styX allowlist rejects %s: IPv6 allow rules must be /%d or narrower", prefix, styxMinAllowPrefixBitsV6)
	}
	return prefix, nil
}

// StyxNormalizeDestination canonicalises a traffic destination for policy
// evaluation. IPv4-mapped IPv6 addresses are unmapped first, so
// ::ffff:169.254.169.254 cannot bypass the veto or the allowlist.
func StyxNormalizeDestination(destination netip.Addr) (netip.Addr, error) {
	if !destination.IsValid() {
		return netip.Addr{}, errors.New("styX destination is not a valid IP address")
	}
	destination = destination.Unmap()
	if !destination.Is4() && !destination.Is6() {
		return netip.Addr{}, errors.New("styX destination has no supported address family")
	}
	if destination.IsUnspecified() {
		return netip.Addr{}, errors.New("styX destination is the unspecified address")
	}
	return destination, nil
}

// StyxMetadataVetoMatch reports the veto prefix a destination falls into. The
// mandatory veto always wins over the allowlist: there is no operator setting
// that can whitelist a metadata endpoint.
func StyxMetadataVetoMatch(destination netip.Addr) (netip.Prefix, bool) {
	address, err := StyxNormalizeDestination(destination)
	if err != nil {
		return netip.Prefix{}, false
	}
	for _, prefix := range styxMetadataVetoPrefixes {
		if prefix.IsValid() && prefix.Contains(address) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

// StyxICMPv6NDExempt reports the documented exception: IPv6 ICMPv6 neighbour
// solicitation/advertisement (type 135/136) on link-local is not vetoed by
// fe80::/10, because blocking it would break IPv6 neighbour discovery.
func StyxICMPv6NDExempt(proto uint8, icmpType uint8) bool {
	if proto != styxProtoICMPv6 {
		return false
	}
	return icmpType == styxNDTypeNeighborSolicitation || icmpType == styxNDTypeNeighborAdvertisement
}

// StyxValidateBlockablePrefix enforces the minimum specificity of a block rule:
// no derived block may be coarser than a /16 (IPv4) or /32 (IPv6). This keeps a
// single finding from ever turning into a range-wide egress cut.
func StyxValidateBlockablePrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return errors.New("styX block prefix is invalid")
	}
	if prefix.Addr().Is4In6() {
		return fmt.Errorf("styX block prefix %s must not be an IPv4-mapped IPv6 prefix", prefix)
	}
	if prefix != prefix.Masked() {
		return fmt.Errorf("styX block prefix %s is not canonical", prefix)
	}
	if prefix.Addr().IsUnspecified() {
		return fmt.Errorf("styX block prefix %s is the unspecified address", prefix)
	}
	if prefix.Bits() == 0 {
		return errors.New("styX block prefix rejects a /0 rule; no block may cover the whole address space")
	}
	if prefix.Addr().Is4() {
		if prefix.Bits() < StyxMinBlockPrefixBitsV4 {
			return fmt.Errorf("styX block prefix %s is broader than the /%d IPv4 boundary", prefix, StyxMinBlockPrefixBitsV4)
		}
		return nil
	}
	if prefix.Bits() < StyxMinBlockPrefixBitsV6 {
		return fmt.Errorf("styX block prefix %s is broader than the /%d IPv6 boundary", prefix, StyxMinBlockPrefixBitsV6)
	}
	return nil
}

// StyxBlockableHostPrefix derives the host block target for one signed
// destination. It never widens a finding beyond the single address it proves.
func StyxBlockableHostPrefix(destination netip.Addr) (netip.Prefix, error) {
	address, err := StyxNormalizeDestination(destination)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix := netip.PrefixFrom(address, address.BitLen())
	if err := StyxValidateBlockablePrefix(prefix); err != nil {
		return netip.Prefix{}, err
	}
	return prefix, nil
}

// StyxPolicyVerdict is the ordered pipeline outcome of one destination
// evaluation. The order is: mode off, invalid target, loopback exemption, ND
// exemption, mandatory metadata veto, DNS pin, allowlist, default-deny.
type StyxPolicyVerdict string

const (
	StyxVerdictModeOff        StyxPolicyVerdict = "mode-off"
	StyxVerdictInvalidTarget  StyxPolicyVerdict = "invalid-target"
	StyxVerdictLoopbackExempt StyxPolicyVerdict = "loopback-exempt"
	StyxVerdictNDExempt       StyxPolicyVerdict = "icmpv6-nd-exempt"
	StyxVerdictMetadataVeto   StyxPolicyVerdict = "metadata-veto"
	StyxVerdictDNSVeto        StyxPolicyVerdict = "dns-veto"
	StyxVerdictDNSResolver    StyxPolicyVerdict = "dns-resolver"
	StyxVerdictAllowlist      StyxPolicyVerdict = "allowlist"
	StyxVerdictDefaultDeny    StyxPolicyVerdict = "default-deny"
)

// StyxPolicyRequest is one read-only policy question. Proto is the IP protocol
// number (6 TCP, 17 UDP, 58 ICMPv6, 0 neutral); ICMPType is only meaningful for
// protocol 58 and feeds the neighbour-discovery exemption.
type StyxPolicyRequest struct {
	Destination netip.Addr `json:"destination"`
	Port        uint16     `json:"port"`
	Proto       uint8      `json:"proto"`
	ICMPType    uint8      `json:"icmpType"`
}

// StyxPolicyDecision is the resolved verdict. In observe mode a would-be block
// is reported (WouldBlock) but never enforced; only mode=enforce sets
// Allowed=false and Enforced=true.
type StyxPolicyDecision struct {
	Verdict       StyxPolicyVerdict `json:"verdict"`
	Mode          string            `json:"mode"`
	Allowed       bool              `json:"allowed"`
	WouldBlock    bool              `json:"wouldBlock"`
	Enforced      bool              `json:"enforced"`
	Destination   string            `json:"destination"`
	MatchedPrefix string            `json:"matchedPrefix,omitempty"`
	Reason        string            `json:"reason"`
}

// StyxEvaluatePolicy resolves one destination against the mandatory veto, the
// DNS pin, the operator allowlist and default-deny. It is a pure function and
// is the single conflict/veto resolver of the Windows StyX port.
func StyxEvaluatePolicy(settings StyxSettings, request StyxPolicyRequest) StyxPolicyDecision {
	mode := settings.EffectiveMode()
	decision := StyxPolicyDecision{Destination: request.Destination.String(), Mode: mode}
	if mode == StyxModeOff {
		decision.Verdict = StyxVerdictModeOff
		decision.Allowed = true
		decision.Reason = "styX is off; no egress policy is evaluated"
		return decision
	}
	destination, err := StyxNormalizeDestination(request.Destination)
	if err != nil {
		decision.Verdict = StyxVerdictInvalidTarget
		decision.Reason = "destination rejected: " + err.Error()
		decision.WouldBlock = true
		decision.Allowed = mode != StyxModeEnforce
		decision.Enforced = !decision.Allowed
		return decision
	}
	decision.Destination = destination.String()
	if destination.IsLoopback() {
		decision.Verdict = StyxVerdictLoopbackExempt
		decision.Allowed = true
		decision.Reason = "loopback is exempt from the StyX veto, DNS pin and default-deny"
		return decision
	}
	if StyxICMPv6NDExempt(request.Proto, request.ICMPType) && destination.Is6() && destination.IsLinkLocalUnicast() {
		decision.Verdict = StyxVerdictNDExempt
		decision.Allowed = true
		decision.Reason = "ICMPv6 neighbour discovery on link-local is exempt from the fe80::/10 veto"
		return decision
	}
	if matched, vetoed := StyxMetadataVetoMatch(destination); vetoed {
		decision.MatchedPrefix = matched.String()
		styxResolveBlockDecision(&decision, mode, StyxVerdictMetadataVeto,
			fmt.Sprintf("destination is inside the mandatory metadata/link-local/multicast veto %s", matched))
		return decision
	}
	if request.Proto == styxProtoTCP || request.Proto == styxProtoUDP {
		if request.Port == StyXDNSPlainPort || request.Port == StyXDNSDoTLSPort {
			if matched, found := styxMatchPrefixTexts(settings.DNSResolvers, destination); found {
				decision.Verdict = StyxVerdictDNSResolver
				decision.Allowed = true
				decision.MatchedPrefix = matched.String()
				decision.Reason = "DNS traffic to the configured resolver " + matched.String() + " is permitted"
				return decision
			}
			styxResolveBlockDecision(&decision, mode, StyxVerdictDNSVeto,
				fmt.Sprintf("DNS port %d is only permitted to a configured resolver prefix", request.Port))
			return decision
		}
	}
	if matched, found := styxMatchPrefixTexts(settings.Allowlist, destination); found {
		decision.Verdict = StyxVerdictAllowlist
		decision.Allowed = true
		decision.MatchedPrefix = matched.String()
		decision.Reason = "destination is covered by the operator allowlist " + matched.String()
		return decision
	}
	styxResolveBlockDecision(&decision, mode, StyxVerdictDefaultDeny,
		"no allowlist entry matches and default-deny is the StyX default")
	return decision
}

// styxResolveBlockDecision marks a would-block verdict and applies it only in
// enforce mode; observe mode records the decision without dropping traffic.
func styxResolveBlockDecision(decision *StyxPolicyDecision, mode string, verdict StyxPolicyVerdict, reason string) {
	decision.Verdict = verdict
	decision.Reason = reason
	decision.WouldBlock = true
	if mode == StyxModeEnforce {
		decision.Allowed = false
		decision.Enforced = true
		return
	}
	decision.Allowed = true
	decision.Enforced = false
}

// styxMatchPrefixTexts matches one destination against already validated
// settings strings. Parse errors are impossible for normalised settings and are
// skipped fail-closed (the next stage still applies).
func styxMatchPrefixTexts(texts []string, destination netip.Addr) (netip.Prefix, bool) {
	for _, text := range texts {
		prefix, err := StyxCanonicalPrefix(text)
		if err != nil {
			continue
		}
		if prefix.Contains(destination) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

// styxPrefixesOverlap reports whether two canonical prefixes intersect.
func styxPrefixesOverlap(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}
