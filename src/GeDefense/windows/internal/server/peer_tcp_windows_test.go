// STATUS: PLATIN VGT SUPREME
//go:build windows

package server

import (
	"encoding/binary"
	"testing"
)

// tcpPortValue encodes a host-order port the way MIB_TCPROW_OWNER_PID stores it
// (network byte order inside the DWORD).
func tcpPortValue(port uint16) uint32 {
	return uint32((port&0x00FF)<<8 | (port>>8)&0xFF)
}

func tcp4Row(state, localAddr uint32, localPort uint16, remoteAddr uint32, remotePort uint16, pid uint32) []byte {
	row := make([]byte, 24)
	binary.LittleEndian.PutUint32(row[0:4], state)
	binary.LittleEndian.PutUint32(row[4:8], localAddr)
	binary.LittleEndian.PutUint32(row[8:12], tcpPortValue(localPort))
	binary.LittleEndian.PutUint32(row[12:16], remoteAddr)
	binary.LittleEndian.PutUint32(row[16:20], tcpPortValue(remotePort))
	binary.LittleEndian.PutUint32(row[20:24], pid)
	return row
}

func tcp4Table(rows ...[]byte) []byte {
	table := make([]byte, 4+24*len(rows))
	binary.LittleEndian.PutUint32(table[0:4], uint32(len(rows)))
	for index, row := range rows {
		copy(table[4+index*24:4+(index+1)*24], row)
	}
	return table
}

func tcp6Row(state uint32, localAddr []byte, localPort uint16, remoteAddr []byte, remotePort uint16, pid uint32) []byte {
	row := make([]byte, 56)
	copy(row[0:16], localAddr)
	binary.LittleEndian.PutUint32(row[20:24], tcpPortValue(localPort))
	copy(row[24:40], remoteAddr)
	binary.LittleEndian.PutUint32(row[44:48], tcpPortValue(remotePort))
	binary.LittleEndian.PutUint32(row[48:52], state)
	binary.LittleEndian.PutUint32(row[52:56], pid)
	return row
}

func tcp6Table(rows ...[]byte) []byte {
	table := make([]byte, 4+56*len(rows))
	binary.LittleEndian.PutUint32(table[0:4], uint32(len(rows)))
	for index, row := range rows {
		copy(table[4+index*56:4+(index+1)*56], row)
	}
	return table
}

func TestTCPOwnerIPv4RowPredicates(t *testing.T) {
	const (
		serverHost  = uint32(0x0100007F) // 127.0.0.1 in table layout
		nonLoopback = uint32(0x0500000A)
		clientPort  = uint16(49152)
		serverPort  = uint16(17831)
		clientPID   = uint32(4242)
	)
	valid := tcp4Row(tcpStateEstablished, loopbackIPv4, clientPort, serverHost, serverPort, clientPID)
	tests := []struct {
		name  string
		table []byte
		want  uint32
		fail  bool
	}{
		{
			name:  "established loopback owner",
			table: tcp4Table(valid),
			want:  clientPID,
		},
		{
			name:  "non-established row ignored",
			table: tcp4Table(tcp4Row(tcpStateEstablished+1, loopbackIPv4, clientPort, serverHost, serverPort, clientPID)),
			fail:  true,
		},
		{
			name:  "non-loopback local address ignored",
			table: tcp4Table(tcp4Row(tcpStateEstablished, nonLoopback, clientPort, serverHost, serverPort, clientPID)),
			fail:  true,
		},
		{
			name:  "wrong remote address ignored",
			table: tcp4Table(tcp4Row(tcpStateEstablished, loopbackIPv4, clientPort, nonLoopback, serverPort, clientPID)),
			fail:  true,
		},
		{
			name:  "wrong local port ignored",
			table: tcp4Table(tcp4Row(tcpStateEstablished, loopbackIPv4, clientPort+1, serverHost, serverPort, clientPID)),
			fail:  true,
		},
		{
			name:  "zero pid ignored",
			table: tcp4Table(tcp4Row(tcpStateEstablished, loopbackIPv4, clientPort, serverHost, serverPort, 0)),
			fail:  true,
		},
		{
			name: "newest decoy row does not mask the match",
			table: tcp4Table(
				tcp4Row(tcpStateEstablished+1, loopbackIPv4, clientPort, serverHost, serverPort, 1111),
				valid,
			),
			want: clientPID,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			pid, err := tcpOwnerIPv4FromTable(testCase.table, serverHost, serverPort, clientPort)
			if testCase.fail {
				if err == nil {
					t.Fatalf("row was accepted with pid=%d", pid)
				}
				return
			}
			if err != nil || pid != testCase.want {
				t.Fatalf("pid=%d err=%v, want %d", pid, err, testCase.want)
			}
		})
	}
}

func TestTCPOwnerIPv6RowPredicates(t *testing.T) {
	const (
		clientPort = uint16(49200)
		serverPort = uint16(17831)
		clientPID  = uint32(5252)
	)
	loopback := loopbackIPv6
	valid := tcp6Row(tcpStateEstablished, loopback, clientPort, loopback, serverPort, clientPID)
	if pid, err := tcpOwnerIPv6FromTable(tcp6Table(valid), loopback, serverPort, clientPort); err != nil || pid != clientPID {
		t.Fatalf("loopback IPv6 row = %d, err=%v", pid, err)
	}
	nonLoopback := make([]byte, 16)
	nonLoopback[0] = 0xFE
	tests := map[string][]byte{
		"non-established":            tcp6Table(tcp6Row(tcpStateEstablished+1, loopback, clientPort, loopback, serverPort, clientPID)),
		"non-loopback local address": tcp6Table(tcp6Row(tcpStateEstablished, nonLoopback, clientPort, loopback, serverPort, clientPID)),
		"wrong remote address":       tcp6Table(tcp6Row(tcpStateEstablished, loopback, clientPort, nonLoopback, serverPort, clientPID)),
		"zero pid":                   tcp6Table(tcp6Row(tcpStateEstablished, loopback, clientPort, loopback, serverPort, 0)),
	}
	for name, table := range tests {
		if _, err := tcpOwnerIPv6FromTable(table, loopback, serverPort, clientPort); err == nil {
			t.Fatalf("%s IPv6 row was accepted", name)
		}
	}
}

func TestProcessLineageRequiresPlausibleCreationTimes(t *testing.T) {
	relations := map[uint32]uint32{100: 50, 50: 10}
	rel := func(pid uint32) (uint32, bool) {
		parent, ok := relations[pid]
		return parent, ok
	}
	times := map[uint32]int64{100: 1_000_000_000, 50: 500_000_000, 10: 100_000_000}
	clock := func(pid uint32) int64 { return times[pid] }

	if !descendsFromLineage(100, 10, rel, clock) {
		t.Fatal("plausible ancestry chain rejected")
	}
	if !descendsFromLineage(100, 100, rel, clock) {
		t.Fatal("process must be its own ancestry root")
	}

	// Parent created clearly after the child is impossible: recycle/forgery.
	badTimes := map[uint32]int64{100: 1_000_000_000, 50: 5_000_000_000, 10: 100_000_000}
	badClock := func(pid uint32) int64 { return badTimes[pid] }
	if descendsFromLineage(100, 10, rel, badClock) {
		t.Fatal("impossible creation-time ancestry accepted")
	}

	// Small clock skew inside the tolerance is accepted.
	skewTimes := map[uint32]int64{100: 1_000_000_000, 50: 1_000_000_000 + processCreationToleranceNanos/2, 10: 100_000_000}
	skewClock := func(pid uint32) int64 { return skewTimes[pid] }
	if !descendsFromLineage(100, 10, rel, skewClock) {
		t.Fatal("tolerated creation-time skew rejected")
	}

	// Unknown creation time fails closed.
	missingClock := func(pid uint32) int64 {
		if pid == 50 {
			return 0
		}
		return times[pid]
	}
	if descendsFromLineage(100, 10, rel, missingClock) {
		t.Fatal("missing creation time accepted")
	}

	// Cycle protection.
	cycle := map[uint32]uint32{100: 50, 50: 100}
	cycleRel := func(pid uint32) (uint32, bool) {
		parent, ok := cycle[pid]
		return parent, ok
	}
	if descendsFromLineage(100, 999, cycleRel, func(uint32) int64 { return 1 }) {
		t.Fatal("parent cycle accepted")
	}

	// Depth limit.
	deep := make(map[uint32]uint32, processLineageMaxDepth+4)
	deepTimes := make(map[uint32]int64, processLineageMaxDepth+4)
	for index := uint32(0); index < processLineageMaxDepth+3; index++ {
		deep[1000+index] = 1000 + index + 1
		deepTimes[1000+index] = int64(index) + 1
	}
	deepRel := func(pid uint32) (uint32, bool) {
		parent, ok := deep[pid]
		return parent, ok
	}
	deepClock := func(pid uint32) int64 { return deepTimes[pid] }
	if descendsFromLineage(1000, 1000+processLineageMaxDepth+2, deepRel, deepClock) {
		t.Fatal("ancestry beyond the depth limit accepted")
	}
}
