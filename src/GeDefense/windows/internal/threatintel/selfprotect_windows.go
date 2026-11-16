// STATUS: PLATIN VGT SUPREME
//go:build windows

package threatintel

// FIND-WIN-015: host resolver discovery for the network self-protection veto.
//
// The compiler must never block the DNS resolver the host uses for feed
// downloads, updates or the control plane. The Windows IP Helper API
// (GetNetworkParams) returns the configured DNS server list without any external
// Go dependency. The call is bounded (64 KiB, at most 32 addresses), follows the
// documented IP_ADDR_STRING linked list defensively and degrades to "no veto
// entries" on any failure: the static self-protection ranges still apply, and a
// failed resolver query can only widen enforcement, never weaken validation.

import (
	"bytes"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	// Layout constants from iptypes.h / iptypes.h FIXED_INFO.
	fixedMaxHostnameLen   = 128 + 4
	fixedMaxDomainNameLen = 128 + 4
	fixedMaxScopeIDLen    = 256 + 4
	// ipAddrStringCount bounds the linked-list walk. A workstation has a handful
	// of resolvers; more than this is treated as a hostile/broken configuration.
	ipAddrStringCount = 32
	// resolverBufferLimit bounds the GetNetworkParams allocation.
	resolverBufferLimit = 64 << 10
	// errorBufferOverflow is ERROR_BUFFER_OVERFLOW, the documented result of the
	// size-probing call.
	errorBufferOverflow = 111
)

// ipAddrString mirrors IP_ADDR_STRING (iptypes.h): a linked list of IPv4
// resolver entries. The IPv6 resolver list is not part of FIXED_INFO; the static
// self-protection ranges cover the IPv6 control plane (loopback, link-local,
// multicast, EC2 metadata).
type ipAddrString struct {
	Next      *ipAddrString
	IpAddress [16]byte
	IpMask    [16]byte
	Context   uint32
}

// fixedInfo mirrors FIXED_INFO (iptypes.h). Only DnsServerList is consumed.
type fixedInfo struct {
	HostName      [fixedMaxHostnameLen]byte
	DomainName    [fixedMaxDomainNameLen]byte
	CurrentDNS    *ipAddrString
	DNSServerList ipAddrString
	NodeType      uint32
	ScopeID       [fixedMaxScopeIDLen]byte
	EnableRouting uint32
	EnableProxy   uint32
	EnableDNS     uint32
}

var (
	ipHelperDLL           = syscall.NewLazyDLL("iphlpapi.dll")
	procGetNetworkParamsW = ipHelperDLL.NewProc("GetNetworkParams")
)

// platformResolverAddresses returns the configured IPv4 DNS resolver addresses.
func platformResolverAddresses() []netip.Addr {
	var size uint32
	result, _, _ := procGetNetworkParamsW.Call(0, uintptr(unsafe.Pointer(&size)))
	if result != errorBufferOverflow || size == 0 || size > resolverBufferLimit {
		return nil
	}
	buffer := make([]byte, size)
	result, _, _ = procGetNetworkParamsW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if result != 0 {
		return nil
	}
	info := (*fixedInfo)(unsafe.Pointer(&buffer[0]))
	addresses := make([]netip.Addr, 0, 4)
	seen := make(map[netip.Addr]struct{}, 4)
	node := &info.DNSServerList
	for depth := 0; depth < ipAddrStringCount && node != nil; depth++ {
		if address, ok := parseResolverEntry(node.IpAddress[:]); ok {
			if _, duplicate := seen[address]; !duplicate {
				seen[address] = struct{}{}
				addresses = append(addresses, address)
			}
		}
		node = node.Next
	}
	// The linked-list pointers point into buffer; keep it alive while they are
	// dereferenced above and do not let the GC move it (Go's GC never moves heap
	// objects, but the explicit keep-alive documents the unsafe lifetime).
	runtime.KeepAlive(buffer)
	return addresses
}

// parseResolverEntry parses one NUL-terminated IPv4 address string.
func parseResolverEntry(raw []byte) (netip.Addr, bool) {
	if index := bytes.IndexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	if len(raw) == 0 {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(string(raw))
	if err != nil || !address.Is4() || address.IsUnspecified() {
		return netip.Addr{}, false
	}
	return address, true
}
