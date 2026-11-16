// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

// Per-connection TCP extended statistics (TCP_ESTATS) binding.
//
// This is the optional Win32 telemetry source of the Windows V6 StyX port. It
// binds exactly two documented iphlpapi entry points:
//
//   - SetPerTcpConnectionEStats(..., TcpConnectionEstatsData, TCP_ESTATS_DATA_RW_v0)
//     to enable data collection for one connection,
//   - GetPerTcpConnectionEStats(..., TcpConnectionEstatsData, ..., TCP_ESTATS_DATA_ROD_v0)
//     to read the read-only data counters (DataBytesOut/DataBytesIn at minimum).
//
// The IPv6 variants (SetPerTcp6ConnectionEStats/GetPerTcp6ConnectionEStats) use
// the documented MIB_TCP6ROW layout. Struct layouts are pinned by tests because
// a wrong size or offset makes every query fail with an opaque Win32 error.
//
// Honesty rules of this file: a connection that cannot be addressed or queried
// returns an error, never zeroed statistics. The caller (internal/mhx StyX
// collector) must keep RxObservationAvailable=false unless a Get call actually
// succeeded.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	// TCPStateEstablished is MIB_TCP_STATE_ESTAB (the only state whose
	// per-connection data counters are useful for egress telemetry).
	TCPStateEstablished uint32 = 5

	// TCPEstatsDataRWV0Version / TCPEstatsDataRODV0Version are the only struct
	// versions defined for the data row of TCP_ESTATS.
	TCPEstatsDataRWV0Version  uint32 = 0
	TCPEstatsDataRODV0Version uint32 = 0

	// tcpConnectionEstatsData is TCP_ESTATS_TYPE TcpConnectionEstatsData (1).
	tcpConnectionEstatsData = 1

	// tcpEstatsDataRODV0Size is sizeof(TCP_ESTATS_DATA_ROD_v0) from the Windows
	// SDK: six ULONG64, five ULONG, two 4-byte pads and two more ULONG64.
	tcpEstatsDataRODV0Size = 96

	// mibTCPRowSize / mibTCP6RowSize are the documented MIB_TCPROW (20 bytes) and
	// MIB_TCP6ROW (52 bytes) sizes.
	mibTCPRowSize  = 20
	mibTCP6RowSize = 52
)

var (
	procSetPerTcpConnectionEStats  = iphlpapi.NewProc("SetPerTcpConnectionEStats")
	procGetPerTcpConnectionEStats  = iphlpapi.NewProc("GetPerTcpConnectionEStats")
	procSetPerTcp6ConnectionEStats = iphlpapi.NewProc("SetPerTcp6ConnectionEStats")
	procGetPerTcp6ConnectionEStats = iphlpapi.NewProc("GetPerTcp6ConnectionEStats")
)

// TCPConnDataStats is the honest projection of TCP_ESTATS_DATA_ROD_v0.
type TCPConnDataStats struct {
	DataBytesOut      uint64
	DataBytesIn       uint64
	DataSegsOut       uint64
	DataSegsIn        uint64
	SegsOut           uint64
	SegsIn            uint64
	SoftErrors        uint32
	SoftErrorReason   uint32
	SndUna            uint32
	SndNxt            uint32
	SndMax            uint32
	ThruBytesAcked    uint64
	RcvNxt            uint32
	ThruBytesReceived uint64
}

// tcpEstatsDataRWv0 mirrors TCP_ESTATS_DATA_RW_v0 (one BOOLEAN).
type tcpEstatsDataRWv0 struct {
	EnableCollection uint8
}

// tcpEstatsDataRODv0 mirrors TCP_ESTATS_DATA_ROD_v0. The explicit pad fields
// reproduce the Windows ABI on 386 as well (MSVC aligns ULONG64 members to 8),
// so the struct is 96 bytes on every Windows target, matching the SDK.
type tcpEstatsDataRODv0 struct {
	DataBytesOut      uint64
	DataBytesIn       uint64
	DataSegsOut       uint64
	DataSegsIn        uint64
	SegsOut           uint64
	SegsIn            uint64
	SoftErrors        uint32
	SoftErrorReason   uint32
	SndUna            uint32
	SndNxt            uint32
	SndMax            uint32
	_                 uint32
	ThruBytesAcked    uint64
	RcvNxt            uint32
	_                 uint32
	ThruBytesReceived uint64
}

// mibTCPRow mirrors MIB_TCPROW (IPv4).
type mibTCPRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
}

// mibTCP6Row mirrors MIB_TCP6ROW (IPv6); the scope ids are numeric interface
// indices, not zone names.
type mibTCP6Row struct {
	State         uint32
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
}

// EnableTCPConnectionDataEstats turns on TCP_ESTATS_DATA collection for one
// connection. The query is idempotent; a connection that cannot be addressed
// yields an error.
func EnableTCPConnectionDataEstats(connection TCPConnection) error {
	local, remote, err := validateTCPEstatsConnection(connection)
	if err != nil {
		return err
	}
	rw := tcpEstatsDataRWv0{EnableCollection: 1}
	if local.Is4() {
		row, rowErr := tcpEstatsRow(connection, local, remote)
		if rowErr != nil {
			return rowErr
		}
		result, _, callErr := procSetPerTcpConnectionEStats.Call(
			uintptr(unsafe.Pointer(&row)),
			uintptr(tcpConnectionEstatsData),
			uintptr(unsafe.Pointer(&rw)),
			uintptr(TCPEstatsDataRWV0Version),
			unsafe.Sizeof(rw),
			0, 0, 0,
			0, 0, 0,
		)
		return tcpEstatsCallError("SetPerTcpConnectionEStats", result, callErr)
	}
	row, rowErr := tcpEstats6Row(connection, local, remote)
	if rowErr != nil {
		return rowErr
	}
	result, _, callErr := procSetPerTcp6ConnectionEStats.Call(
		uintptr(unsafe.Pointer(&row)),
		uintptr(tcpConnectionEstatsData),
		uintptr(unsafe.Pointer(&rw)),
		uintptr(TCPEstatsDataRWV0Version),
		unsafe.Sizeof(rw),
		0, 0, 0,
		0, 0, 0,
	)
	return tcpEstatsCallError("SetPerTcp6ConnectionEStats", result, callErr)
}

// TCPConnectionDataEstats reads the per-connection data counters. It returns an
// error whenever the row cannot be resolved or the statistics are not available
// (for example because collection was never enabled); it never guesses zeroes.
func TCPConnectionDataEstats(connection TCPConnection) (TCPConnDataStats, error) {
	local, remote, err := validateTCPEstatsConnection(connection)
	if err != nil {
		return TCPConnDataStats{}, err
	}
	var rod tcpEstatsDataRODv0
	if local.Is4() {
		row, rowErr := tcpEstatsRow(connection, local, remote)
		if rowErr != nil {
			return TCPConnDataStats{}, rowErr
		}
		result, _, callErr := procGetPerTcpConnectionEStats.Call(
			uintptr(unsafe.Pointer(&row)),
			uintptr(tcpConnectionEstatsData),
			0, 0, 0,
			0, 0, 0,
			uintptr(unsafe.Pointer(&rod)),
			uintptr(TCPEstatsDataRODV0Version),
			unsafe.Sizeof(rod),
		)
		if callErr := tcpEstatsCallError("GetPerTcpConnectionEStats", result, callErr); callErr != nil {
			return TCPConnDataStats{}, callErr
		}
		return tcpConnDataStatsFromROD(rod), nil
	}
	row, rowErr := tcpEstats6Row(connection, local, remote)
	if rowErr != nil {
		return TCPConnDataStats{}, rowErr
	}
	result, _, callErr := procGetPerTcp6ConnectionEStats.Call(
		uintptr(unsafe.Pointer(&row)),
		uintptr(tcpConnectionEstatsData),
		0, 0, 0,
		0, 0, 0,
		uintptr(unsafe.Pointer(&rod)),
		uintptr(TCPEstatsDataRODV0Version),
		unsafe.Sizeof(rod),
	)
	if callErr := tcpEstatsCallError("GetPerTcp6ConnectionEStats", result, callErr); callErr != nil {
		return TCPConnDataStats{}, callErr
	}
	return tcpConnDataStatsFromROD(rod), nil
}

// validateTCPEstatsConnection rejects rows that cannot address a real
// connection: invalid or unspecified addresses, mixed families, port 0 and an
// unknown TCP state.
func validateTCPEstatsConnection(connection TCPConnection) (netip.Addr, netip.Addr, error) {
	local := connection.LocalAddr
	remote := connection.RemoteAddr
	if !local.IsValid() || !remote.IsValid() {
		return netip.Addr{}, netip.Addr{}, errors.New("TCP_ESTATS connection requires valid local and remote addresses")
	}
	local = local.Unmap()
	remote = remote.Unmap()
	if local.IsUnspecified() || remote.IsUnspecified() {
		return netip.Addr{}, netip.Addr{}, errors.New("TCP_ESTATS connection must not use the unspecified address")
	}
	if local.Is4() != remote.Is4() {
		return netip.Addr{}, netip.Addr{}, errors.New("TCP_ESTATS connection has mismatched address families")
	}
	if connection.LocalPort == 0 || connection.RemotePort == 0 {
		return netip.Addr{}, netip.Addr{}, errors.New("TCP_ESTATS connection requires non-zero local and remote ports")
	}
	if connection.State == 0 || connection.State > 12 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("TCP_ESTATS connection state %d is not a MIB_TCP_STATE", connection.State)
	}
	return local, remote, nil
}

func tcpEstatsRow(connection TCPConnection, local, remote netip.Addr) (mibTCPRow, error) {
	if !local.Is4() || !remote.Is4() {
		return mibTCPRow{}, errors.New("MIB_TCPROW requires IPv4 connection endpoints")
	}
	localBytes := local.As4()
	remoteBytes := remote.As4()
	return mibTCPRow{
		State:      connection.State,
		LocalAddr:  binary.LittleEndian.Uint32(localBytes[:]),
		LocalPort:  mibTCPPort(connection.LocalPort),
		RemoteAddr: binary.LittleEndian.Uint32(remoteBytes[:]),
		RemotePort: mibTCPPort(connection.RemotePort),
	}, nil
}

func tcpEstats6Row(connection TCPConnection, local, remote netip.Addr) (mibTCP6Row, error) {
	if !local.Is6() || !remote.Is6() {
		return mibTCP6Row{}, errors.New("MIB_TCP6ROW requires IPv6 connection endpoints")
	}
	localScope, err := tcpEstatsScopeID(connection.LocalAddr)
	if err != nil {
		return mibTCP6Row{}, err
	}
	remoteScope, err := tcpEstatsScopeID(connection.RemoteAddr)
	if err != nil {
		return mibTCP6Row{}, err
	}
	localBytes := local.As16()
	remoteBytes := remote.As16()
	return mibTCP6Row{
		State:         connection.State,
		LocalAddr:     localBytes,
		LocalScopeID:  localScope,
		LocalPort:     mibTCPPort(connection.LocalPort),
		RemoteAddr:    remoteBytes,
		RemoteScopeID: remoteScope,
		RemotePort:    mibTCPPort(connection.RemotePort),
	}, nil
}

// mibTCPPort encodes one host-order port into the MIB row representation: the
// low 16 bits of the DWORD carry the port in network byte order.
func mibTCPPort(port uint16) uint32 {
	return uint32(port>>8) | uint32(port&0xff)<<8
}

// tcpEstatsScopeID converts an IPv6 zone to the numeric scope id the MIB row
// needs. Numeric zones only: guessing an interface index would query the wrong
// connection, so an unresolvable zone is an error.
func tcpEstatsScopeID(address netip.Addr) (uint32, error) {
	zone := address.Zone()
	if zone == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(zone, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("TCP_ESTATS IPv6 zone %q is not a numeric scope id", zone)
	}
	return uint32(parsed), nil
}

// tcpEstatsCallError converts a ULONG iphlpapi return value into a joined error.
// errnoResult drops the stale last-error that a successful call may leave behind.
func tcpEstatsCallError(operation string, result uintptr, callErr error) error {
	code := uint32(result)
	if code == 0 {
		return nil
	}
	return errors.Join(
		fmt.Errorf("%s failed (win32 error %d): %w", operation, code, syscall.Errno(code)),
		errnoResult(callErr),
	)
}

func tcpConnDataStatsFromROD(rod tcpEstatsDataRODv0) TCPConnDataStats {
	return TCPConnDataStats{
		DataBytesOut:      rod.DataBytesOut,
		DataBytesIn:       rod.DataBytesIn,
		DataSegsOut:       rod.DataSegsOut,
		DataSegsIn:        rod.DataSegsIn,
		SegsOut:           rod.SegsOut,
		SegsIn:            rod.SegsIn,
		SoftErrors:        rod.SoftErrors,
		SoftErrorReason:   rod.SoftErrorReason,
		SndUna:            rod.SndUna,
		SndNxt:            rod.SndNxt,
		SndMax:            rod.SndMax,
		ThruBytesAcked:    rod.ThruBytesAcked,
		RcvNxt:            rod.RcvNxt,
		ThruBytesReceived: rod.ThruBytesReceived,
	}
}
