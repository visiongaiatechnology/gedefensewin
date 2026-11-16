// STATUS: PLATIN VGT SUPREME
//go:build !windows

package threatintel

import "net/netip"

// platformResolverAddresses is the non-Windows stub: the shipped product is a
// Windows service, and the static self-protection ranges (loopback, link-local,
// multicast, IMDS) still apply on every platform. No dynamic resolver veto is
// claimed where the platform query is unavailable.
func platformResolverAddresses() []netip.Addr {
	return nil
}
