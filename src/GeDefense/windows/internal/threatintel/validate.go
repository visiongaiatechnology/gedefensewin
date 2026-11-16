// STATUS: PLATIN VGT SUPREME
package threatintel

import (
	"errors"
	"net/netip"
	"strings"
)

const (
	// minimumThreatV4Bits is the broadest IPv4 enforcement prefix an upstream
	// feed may contribute. FIND-WIN-015: a /8 (or broader) block can contain the
	// host's own resolver, CDN, telemetry or update endpoints and turn a threat
	// feed entry into a self-lockout. /16 is the documented floor.
	minimumThreatV4Bits = 16
	// minimumThreatV6Bits is the IPv6 equivalent floor. /32 keeps the compiler
	// away from whole ISP allocations while still accepting the Spamhaus IPv6 DROP
	// style /32 announcements.
	minimumThreatV6Bits = 32
	// maximumResolverVetoAddresses bounds the per-host resolver veto list so a
	// hostile DNS configuration cannot expand the enforcement subtraction work.
	maximumResolverVetoAddresses = 32
)

// protectedThreatRanges are the historical reserved/special-purpose ranges that
// must never appear in a threat feed or an enforcement projection.
var protectedThreatRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// selfProtectionRanges is the immutable hard veto set (FIND-WIN-015). These
// addresses are the host's own control plane, its DNS path or the cloud instance
// metadata service; blocking them can lock the host out of DNS, management or
// its own CSP control plane. They are rejected as feed indicators and subtracted
// from the compiled enforcement projection even if they arrive through a broader
// (>= /16) feed prefix.
var selfProtectionRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // RFC 3927 link-local incl. 169.254.169.254 IMDS
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud instance metadata
	netip.MustParsePrefix("169.254.170.2/32"),   // Amazon ECS task metadata
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"), // Amazon EC2 IPv6 instance metadata
}

// resolverAddressProvider supplies the host's configured DNS resolver addresses.
// It is a variable so the (Windows-only) IP Helper query can be replaced in
// tests; production always uses the platform implementation.
var resolverAddressProvider = platformResolverAddresses

// selfProtectionVetoPrefixes returns the static self-protection ranges plus a
// /32 (IPv4) or /128 (IPv6) veto for every configured host resolver. The compiler
// subtracts these from the enforcement projection, so a feed prefix that happens
// to cover a resolver can never block the host's DNS path.
func selfProtectionVetoPrefixes() []netip.Prefix {
	result := make([]netip.Prefix, 0, len(selfProtectionRanges)+8)
	result = append(result, selfProtectionRanges...)
	if resolverAddressProvider == nil {
		return result
	}
	addresses := resolverAddressProvider()
	if len(addresses) > maximumResolverVetoAddresses {
		addresses = addresses[:maximumResolverVetoAddresses]
	}
	for _, address := range addresses {
		if !address.IsValid() {
			continue
		}
		address = address.Unmap()
		result = append(result, netip.PrefixFrom(address, address.BitLen()))
	}
	return result
}

func parseThreatToken(token string) (netip.Prefix, error) {
	token = strings.TrimSpace(token)
	if len(token) < 3 || len(token) > 49 || !isThreatToken(token) {
		return netip.Prefix{}, errors.New("threat token rejected")
	}
	if strings.IndexByte(token, '/') >= 0 {
		prefix, err := netip.ParsePrefix(token)
		if err != nil || !validThreatPrefix(prefix) {
			return netip.Prefix{}, errors.New("threat prefix rejected")
		}
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Prefix{}, errors.New("threat address rejected")
	}
	address = address.Unmap()
	prefix := netip.PrefixFrom(address, address.BitLen())
	if !validThreatPrefix(prefix) {
		return netip.Prefix{}, errors.New("threat address rejected")
	}
	return prefix, nil
}

func isThreatToken(value string) bool {
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == '/' {
			continue
		}
		return false
	}
	return true
}

func validThreatPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	prefix = prefix.Masked()
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if prefix.Addr().Is4In6() {
		bits -= 96
	}
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	// FIND-WIN-015: broad self-lockout prefixes are refused outright.
	if (address.Is4() && bits < minimumThreatV4Bits) || (address.Is6() && bits < minimumThreatV6Bits) {
		return false
	}
	canonical := netip.PrefixFrom(address, bits).Masked()
	// Explicit self-protection veto: loopback, link-local, multicast, cloud
	// instance metadata and the host's own control plane are never blockable.
	for _, selfProtection := range selfProtectionRanges {
		if prefixesOverlap(canonical, selfProtection) {
			return false
		}
	}
	for _, protected := range protectedThreatRanges {
		if prefixesOverlap(canonical, protected) {
			return false
		}
	}
	return true
}

func prefixesOverlap(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() {
		return false
	}
	leftAddress := left.Addr().Unmap()
	rightAddress := right.Addr().Unmap()
	if leftAddress.Is4() != rightAddress.Is4() {
		return false
	}
	return left.Contains(rightAddress) || right.Contains(leftAddress)
}
