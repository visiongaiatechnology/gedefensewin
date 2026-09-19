// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"errors"
	"net/netip"
	"strings"
)

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
	if (address.Is4() && bits < 8) || (address.Is6() && bits < 16) {
		return false
	}
	canonical := netip.PrefixFrom(address, bits).Masked()
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
