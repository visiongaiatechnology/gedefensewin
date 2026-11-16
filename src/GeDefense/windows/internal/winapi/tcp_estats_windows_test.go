// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// The TCP_ESTATS structures must match the Windows ABI exactly: a wrong size or
// offset turns every Set/GetPerTcpConnectionEStats call into an opaque failure.
func TestTCPEstatsStructureLayout(t *testing.T) {
	if mibTCPRowSize != 20 || mibTCP6RowSize != 52 || tcpEstatsDataRODV0Size != 96 {
		t.Fatalf("documented SDK sizes drifted: %d/%d/%d", mibTCPRowSize, mibTCP6RowSize, tcpEstatsDataRODV0Size)
	}
	if size := int(unsafe.Sizeof(mibTCPRow{})); size != mibTCPRowSize {
		t.Fatalf("MIB_TCPROW size = %d, want %d", size, mibTCPRowSize)
	}
	if size := int(unsafe.Sizeof(mibTCP6Row{})); size != mibTCP6RowSize {
		t.Fatalf("MIB_TCP6ROW size = %d, want %d", size, mibTCP6RowSize)
	}
	if size := int(unsafe.Sizeof(tcpEstatsDataRWv0{})); size != 1 {
		t.Fatalf("TCP_ESTATS_DATA_RW_v0 size = %d, want 1", size)
	}
	rodSize := int(unsafe.Sizeof(tcpEstatsDataRODv0{}))
	if rodSize != tcpEstatsDataRODV0Size {
		t.Fatalf("TCP_ESTATS_DATA_ROD_v0 size = %d, want %d", rodSize, tcpEstatsDataRODV0Size)
	}

	rowOffsets := map[string]struct{ got, want uintptr }{
		"state":        {unsafe.Offsetof(mibTCPRow{}.State), 0},
		"localAddr":    {unsafe.Offsetof(mibTCPRow{}.LocalAddr), 4},
		"localPort":    {unsafe.Offsetof(mibTCPRow{}.LocalPort), 8},
		"remoteAddr":   {unsafe.Offsetof(mibTCPRow{}.RemoteAddr), 12},
		"remotePort":   {unsafe.Offsetof(mibTCPRow{}.RemotePort), 16},
		"6state":       {unsafe.Offsetof(mibTCP6Row{}.State), 0},
		"6localAddr":   {unsafe.Offsetof(mibTCP6Row{}.LocalAddr), 4},
		"6localScope":  {unsafe.Offsetof(mibTCP6Row{}.LocalScopeID), 20},
		"6localPort":   {unsafe.Offsetof(mibTCP6Row{}.LocalPort), 24},
		"6remoteAddr":  {unsafe.Offsetof(mibTCP6Row{}.RemoteAddr), 28},
		"6remoteScope": {unsafe.Offsetof(mibTCP6Row{}.RemoteScopeID), 44},
		"6remotePort":  {unsafe.Offsetof(mibTCP6Row{}.RemotePort), 48},
	}
	for name, entry := range rowOffsets {
		if entry.got != entry.want {
			t.Fatalf("offset %s = %d, want %d", name, entry.got, entry.want)
		}
	}

	latestOffsets := map[string]struct{ got, want uintptr }{
		"DataBytesOut":      {unsafe.Offsetof(tcpEstatsDataRODv0{}.DataBytesOut), 0},
		"DataBytesIn":       {unsafe.Offsetof(tcpEstatsDataRODv0{}.DataBytesIn), 8},
		"SoftErrors":        {unsafe.Offsetof(tcpEstatsDataRODv0{}.SoftErrors), 48},
		"SoftErrorReason":   {unsafe.Offsetof(tcpEstatsDataRODv0{}.SoftErrorReason), 52},
		"SndUna":            {unsafe.Offsetof(tcpEstatsDataRODv0{}.SndUna), 56},
		"SndNxt":            {unsafe.Offsetof(tcpEstatsDataRODv0{}.SndNxt), 60},
		"SndMax":            {unsafe.Offsetof(tcpEstatsDataRODv0{}.SndMax), 64},
		"ThruBytesAcked":    {unsafe.Offsetof(tcpEstatsDataRODv0{}.ThruBytesAcked), 72},
		"RcvNxt":            {unsafe.Offsetof(tcpEstatsDataRODv0{}.RcvNxt), 80},
		"ThruBytesReceived": {unsafe.Offsetof(tcpEstatsDataRODv0{}.ThruBytesReceived), 88},
	}
	for name, entry := range latestOffsets {
		if entry.got != entry.want {
			t.Fatalf("ROD offset %s = %d, want %d", name, entry.got, entry.want)
		}
	}
}

func TestTCPEstatsMIBPortEncoding(t *testing.T) {
	for _, port := range []uint16{0, 1, 53, 443, 853, 12345, 65535} {
		encoded := mibTCPPort(port)
		decoded := uint16(encoded&0xff)<<8 | uint16(encoded>>8)&0xff
		if decoded != port {
			t.Fatalf("mibTCPPort(%d) decoded as %d", port, decoded)
		}
		if encoded > 0xffff {
			t.Fatalf("mibTCPPort(%d) used bits above the low word: 0x%x", port, encoded)
		}
	}
	if mibTCPPort(443) != 0xbb01 {
		t.Fatalf("mibTCPPort(443) = 0x%x, want 0xbb01 (network byte order)", mibTCPPort(443))
	}
}

func TestTCPEstatsRowEncoding(t *testing.T) {
	connection := TCPConnection{
		PID:        1234,
		State:      TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("10.0.0.5"),
		LocalPort:  50000,
		RemoteAddr: netip.MustParseAddr("203.0.113.9"),
		RemotePort: 443,
	}
	local, remote, err := validateTCPEstatsConnection(connection)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	row, err := tcpEstatsRow(connection, local, remote)
	if err != nil {
		t.Fatalf("v4 row: %v", err)
	}
	if row.State != TCPStateEstablished {
		t.Fatalf("row state = %d", row.State)
	}
	if row.LocalAddr != binary.LittleEndian.Uint32([]byte{10, 0, 0, 5}) {
		t.Fatalf("row local address = 0x%x", row.LocalAddr)
	}
	if row.RemoteAddr != binary.LittleEndian.Uint32([]byte{203, 0, 113, 9}) {
		t.Fatalf("row remote address = 0x%x", row.RemoteAddr)
	}
	if row.LocalPort != mibTCPPort(50000) || row.RemotePort != mibTCPPort(443) {
		t.Fatalf("row ports = %d/%d", row.LocalPort, row.RemotePort)
	}

	v6conn := fakeTCP6RowSource()
	v6local, v6remote, err := validateTCPEstatsConnection(v6conn)
	if err != nil {
		t.Fatalf("validate v6: %v", err)
	}
	v6row, err := tcpEstats6Row(v6conn, v6local, v6remote)
	if err != nil {
		t.Fatalf("v6 row: %v", err)
	}
	wantLocal := netip.MustParseAddr("2001:db8::5").As16()
	if v6row.LocalAddr != wantLocal {
		t.Fatalf("v6 row local address = %v", v6row.LocalAddr)
	}
	if v6row.LocalPort != mibTCPPort(50000) || v6row.RemotePort != mibTCPPort(8443) {
		t.Fatalf("v6 row ports = %d/%d", v6row.LocalPort, v6row.RemotePort)
	}

	// A numeric zone becomes the MIB scope id; a non-numeric zone is an error.
	scoped := TCPConnection{
		State:      TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("fe80::1%7"),
		LocalPort:  50000,
		RemoteAddr: netip.MustParseAddr("fe80::2%9"),
		RemotePort: 443,
	}
	scopeLocal, scopeRemote, err := validateTCPEstatsConnection(scoped)
	if err != nil {
		t.Fatalf("validate scoped: %v", err)
	}
	scopedRow, err := tcpEstats6Row(scoped, scopeLocal, scopeRemote)
	if err != nil || scopedRow.LocalScopeID != 7 || scopedRow.RemoteScopeID != 9 {
		t.Fatalf("scoped row = %+v, %v", scopedRow, err)
	}
	badZone := scoped
	badZone.RemoteAddr = netip.MustParseAddr("fe80::2%eth0")
	badLocal, badRemote, err := validateTCPEstatsConnection(badZone)
	if err != nil {
		t.Fatalf("validate bad zone: %v", err)
	}
	if _, err := tcpEstats6Row(badZone, badLocal, badRemote); err == nil {
		t.Fatal("non-numeric IPv6 zone was silently accepted")
	}
}

func fakeTCP6RowSource() TCPConnection {
	return TCPConnection{
		State:      TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("2001:db8::5"),
		LocalPort:  50000,
		RemoteAddr: netip.MustParseAddr("2001:db8::9"),
		RemotePort: 8443,
	}
}

func TestTCPEstatsConnectionValidation(t *testing.T) {
	valid := []TCPConnection{
		{
			State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 50000,
			RemoteAddr: netip.MustParseAddr("203.0.113.9"), RemotePort: 443,
		},
		fakeTCP6RowSource(),
		{
			State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("::ffff:10.0.0.5"), LocalPort: 50000,
			RemoteAddr: netip.MustParseAddr("::ffff:203.0.113.9"), RemotePort: 443,
		},
	}
	for index, connection := range valid {
		if _, _, err := validateTCPEstatsConnection(connection); err != nil {
			t.Fatalf("valid connection %d rejected: %v", index, err)
		}
	}
	invalid := []TCPConnection{
		{State: TCPStateEstablished, LocalPort: 1, RemotePort: 2},
		{State: 0, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 1, RemoteAddr: netip.MustParseAddr("203.0.113.9"), RemotePort: 2},
		{State: 13, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 1, RemoteAddr: netip.MustParseAddr("203.0.113.9"), RemotePort: 2},
		{State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 0, RemoteAddr: netip.MustParseAddr("203.0.113.9"), RemotePort: 2},
		{State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 1, RemoteAddr: netip.MustParseAddr("203.0.113.9"), RemotePort: 0},
		{State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 1, RemoteAddr: netip.MustParseAddr("2001:db8::9"), RemotePort: 2},
		{State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("0.0.0.0"), LocalPort: 1, RemoteAddr: netip.MustParseAddr("203.0.113.9"), RemotePort: 2},
	}
	for index, connection := range invalid {
		if _, _, err := validateTCPEstatsConnection(connection); err == nil {
			t.Fatalf("invalid connection %d was accepted: %+v", index, connection)
		}
	}
}

func TestTCPEstatsCallError(t *testing.T) {
	if err := tcpEstatsCallError("Test", 0, syscall.Errno(0)); err != nil {
		t.Fatalf("successful call reported error: %v", err)
	}
	err := tcpEstatsCallError("GetPerTcpConnectionEStats", 87, syscall.Errno(0))
	if err == nil {
		t.Fatal("win32 error code was not reported")
	}
	if !errors.Is(err, syscall.Errno(87)) {
		t.Fatalf("win32 error code is not wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "GetPerTcpConnectionEStats") || !strings.Contains(err.Error(), "87") {
		t.Fatalf("error text is not diagnostic: %v", err)
	}
	// A stale last-error on a failing call is joined, a zero errno is dropped.
	joined := tcpEstatsCallError("Test", 5, syscall.Errno(0))
	if joined == nil {
		t.Fatal("failing code without last error was not reported")
	}
	withLastError := tcpEstatsCallError("Test", 5, syscall.Errno(10013))
	if !errors.Is(withLastError, syscall.Errno(5)) || !errors.Is(withLastError, syscall.Errno(10013)) {
		t.Fatalf("joined error does not carry both codes: %v", withLastError)
	}
}

func TestTCPConnDataStatsFromROD(t *testing.T) {
	rod := tcpEstatsDataRODv0{
		DataBytesOut: 11, DataBytesIn: 22, DataSegsOut: 33, DataSegsIn: 44,
		SegsOut: 55, SegsIn: 66, SoftErrors: 77, SoftErrorReason: 88,
		SndUna: 99, SndNxt: 100, SndMax: 101, ThruBytesAcked: 102,
		RcvNxt: 103, ThruBytesReceived: 104,
	}
	stats := tcpConnDataStatsFromROD(rod)
	want := TCPConnDataStats{
		DataBytesOut: 11, DataBytesIn: 22, DataSegsOut: 33, DataSegsIn: 44,
		SegsOut: 55, SegsIn: 66, SoftErrors: 77, SoftErrorReason: 88,
		SndUna: 99, SndNxt: 100, SndMax: 101, ThruBytesAcked: 102,
		RcvNxt: 103, ThruBytesReceived: 104,
	}
	if stats != want {
		t.Fatalf("stats projection = %+v, want %+v", stats, want)
	}
}

// An unaddressable connection must produce an error, never zeroed statistics.
func TestTCPEstatsUnavailableConnectionReturnsError(t *testing.T) {
	unavailable := TCPConnection{
		PID:        4,
		State:      TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("127.0.0.1"),
		LocalPort:  1,
		RemoteAddr: netip.MustParseAddr("203.0.113.1"),
		RemotePort: 9,
	}
	if stats, err := TCPConnectionDataEstats(unavailable); err == nil {
		t.Fatalf("unavailable connection reported stats %+v instead of an error", stats)
	}
	// Enabling collection for a non-existent connection must never panic; a
	// denial/not-found is expected and acceptable.
	_ = EnableTCPConnectionDataEstats(unavailable)

	v6unavailable := TCPConnection{
		PID:        4,
		State:      TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("::1"),
		LocalPort:  2,
		RemoteAddr: netip.MustParseAddr("2001:db8::1"),
		RemotePort: 9,
	}
	if stats, err := TCPConnectionDataEstats(v6unavailable); err == nil {
		t.Fatalf("unavailable IPv6 connection reported stats %+v instead of an error", stats)
	}
	_ = EnableTCPConnectionDataEstats(v6unavailable)

	for _, invalid := range []TCPConnection{
		{},
		{State: TCPStateEstablished, LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 1, RemoteAddr: netip.Addr{}, RemotePort: 2},
	} {
		if _, err := TCPConnectionDataEstats(invalid); err == nil {
			t.Fatalf("invalid connection was queried: %+v", invalid)
		}
		if err := EnableTCPConnectionDataEstats(invalid); err == nil {
			t.Fatalf("invalid connection was enabled: %+v", invalid)
		}
	}
}
