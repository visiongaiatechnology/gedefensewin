// STATUS: PLATIN
//go:build windows

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// The browser bootstrap is bound to the exact process the Center launched, so
// no session secret has to travel through a Chromium command line
// (AN-FIND-002 / UI-FIND-004). This file resolves a loopback peer address to
// the owning process id via the Windows TCP owner table and validates process
// ancestry via a Toolhelp snapshot. Both calls are read-only and need no
// elevation for processes of the same user.

const (
	tcpTableOwnerPIDAll = 5
	// tcpStateEstablished is MIB_TCP_STATE_ESTAB. Only established sockets may
	// identify a peer; TIME_WAIT/LISTEN rows can point at unrelated pids.
	tcpStateEstablished = 5
	// maxTCPTableRows bounds the scan of the kernel-provided owner table.
	maxTCPTableRows = 1 << 16
	// maxProcessEntries bounds the Toolhelp lineage snapshot.
	maxProcessEntries = 8192
	// processLineageMaxDepth bounds the parent-chain walk (cycle protection).
	processLineageMaxDepth = 8
	// processCreationToleranceNanos allows for coarse creation-time resolution
	// when comparing parent and child start times.
	processCreationToleranceNanos = int64(2 * 1000 * 1000 * 1000)
)

var (
	modIPHlpAPI              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCPTable  = modIPHlpAPI.NewProc("GetExtendedTcpTable")
	errPeerLookupUnavailable = errors.New("peer process lookup unavailable")
	// loopbackIPv4 is 127.0.0.1 in the same byte layout the TCP owner table
	// reports for an IN_ADDR (network order bytes in memory).
	loopbackIPv4 = binary.LittleEndian.Uint32([]byte{127, 0, 0, 1})
	loopbackIPv6 = net.IPv6loopback.To16()
)

func lookupPeerProcessID(remoteAddr string) (uint32, error) {
	return lookupPeerProcessIDForPort(remoteAddr, 17831)
}

// lookupPeerProcessIDForPort is the production lookup with the control-plane
// listener port injected so loopback integration tests can exercise the real
// iphlpapi/Toolhelp path against a test listener.
func lookupPeerProcessIDForPort(remoteAddr string, serverPort uint16) (uint32, error) {
	host, portText, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, err
	}
	remotePort, err := strconv.Atoi(portText)
	if err != nil || remotePort < 1 || remotePort > 65535 {
		return 0, errors.New("invalid peer port")
	}
	address := net.ParseIP(host)
	if address == nil {
		return 0, errors.New("invalid peer address")
	}
	if ipv4 := address.To4(); ipv4 != nil {
		return lookupTCPOwnerIPv4(binary.LittleEndian.Uint32(ipv4), serverPort, uint16(remotePort))
	}
	return lookupTCPOwnerIPv6(address.To16(), serverPort, uint16(remotePort))
}

func lookupTCPOwnerIPv4(remoteServerAddr uint32, remoteServerPort, clientLocalPort uint16) (uint32, error) {
	table, err := readExtendedTCPTable(syscall.AF_INET)
	if err != nil {
		return 0, err
	}
	return tcpOwnerIPv4FromTable(table, remoteServerAddr, remoteServerPort, clientLocalPort)
}

// tcpOwnerIPv4FromTable extracts the owning pid of an established, loopback-
// local client socket whose remote endpoint is the control-plane listener. Split
// from the Win32 call so the row predicates are directly testable (FIND-WIN-020).
func tcpOwnerIPv4FromTable(table []byte, remoteServerAddr uint32, remoteServerPort, clientLocalPort uint16) (uint32, error) {
	if len(table) < 4 {
		return 0, errors.New("truncated TCP owner table")
	}
	rows := binary.LittleEndian.Uint32(table[:4])
	if rows > maxTCPTableRows {
		return 0, errors.New("TCP owner table row bound exceeded")
	}
	const rowSize = 24
	if int64(len(table)) < int64(4)+int64(rows)*rowSize {
		return 0, errors.New("truncated TCP owner table")
	}
	for index := uint32(0); index < rows; index++ {
		offset := 4 + int(index)*rowSize
		row := table[offset : offset+rowSize]
		if binary.LittleEndian.Uint32(row[0:4]) != tcpStateEstablished {
			continue
		}
		// The client socket row is the mirror of the accepted server socket:
		// local address must be loopback, local port = server's view of the
		// client port, remote endpoint = the control plane listener.
		if binary.LittleEndian.Uint32(row[4:8]) != loopbackIPv4 {
			continue
		}
		if tcpPort(binary.LittleEndian.Uint32(row[8:12])) != clientLocalPort {
			continue
		}
		if binary.LittleEndian.Uint32(row[12:16]) != remoteServerAddr {
			continue
		}
		if tcpPort(binary.LittleEndian.Uint32(row[16:20])) != remoteServerPort {
			continue
		}
		if pid := binary.LittleEndian.Uint32(row[20:24]); pid != 0 {
			return pid, nil
		}
	}
	return 0, errors.New("peer process not found in TCP owner table")
}

func lookupTCPOwnerIPv6(remoteServerAddr []byte, remoteServerPort, clientLocalPort uint16) (uint32, error) {
	table, err := readExtendedTCPTable(syscall.AF_INET6)
	if err != nil {
		return 0, err
	}
	return tcpOwnerIPv6FromTable(table, remoteServerAddr, remoteServerPort, clientLocalPort)
}

// tcpOwnerIPv6FromTable is the MIB_TCP6ROW_OWNER_PID companion of
// tcpOwnerIPv4FromTable with the same ESTAB + loopback-local predicates.
func tcpOwnerIPv6FromTable(table []byte, remoteServerAddr []byte, remoteServerPort, clientLocalPort uint16) (uint32, error) {
	if len(table) < 4 || len(remoteServerAddr) != 16 {
		return 0, errors.New("truncated TCP owner table")
	}
	rows := binary.LittleEndian.Uint32(table[:4])
	if rows > maxTCPTableRows {
		return 0, errors.New("TCP owner table row bound exceeded")
	}
	const rowSize = 56
	if int64(len(table)) < int64(4)+int64(rows)*rowSize {
		return 0, errors.New("truncated TCP owner table")
	}
	for index := uint32(0); index < rows; index++ {
		offset := 4 + int(index)*rowSize
		row := table[offset : offset+rowSize]
		if binary.LittleEndian.Uint32(row[48:52]) != tcpStateEstablished {
			continue
		}
		if !equalIPv6(row[0:16], loopbackIPv6) {
			continue
		}
		if tcpPort(binary.LittleEndian.Uint32(row[20:24])) != clientLocalPort {
			continue
		}
		if !equalIPv6(row[24:40], remoteServerAddr) {
			continue
		}
		if tcpPort(binary.LittleEndian.Uint32(row[44:48])) != remoteServerPort {
			continue
		}
		if pid := binary.LittleEndian.Uint32(row[52:56]); pid != 0 {
			return pid, nil
		}
	}
	return 0, errors.New("peer process not found in TCP owner table")
}

func equalIPv6(left, right []byte) bool {
	if len(left) != 16 || len(right) != 16 {
		return false
	}
	for index := 0; index < 16; index++ {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// tcpPort converts the network-byte-order port stored in a DWORD of the TCP
// owner table into host order.
func tcpPort(value uint32) uint16 {
	return uint16((value&0xFF)<<8 | (value>>8)&0xFF)
}

func readExtendedTCPTable(addressFamily uint32) ([]byte, error) {
	if err := procGetExtendedTCPTable.Find(); err != nil {
		return nil, errPeerLookupUnavailable
	}
	var size uint32
	_, _, _ = procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(addressFamily), tcpTableOwnerPIDAll, 0)
	if size == 0 {
		size = 64 << 10
	}
	for attempt := 0; attempt < 2; attempt++ {
		buffer := make([]byte, size)
		result, _, _ := procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&size)),
			0, uintptr(addressFamily), tcpTableOwnerPIDAll, 0,
		)
		if result == 0 {
			return buffer[:size], nil
		}
		if syscall.Errno(result) != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, fmt.Errorf("GetExtendedTcpTable failed: %w", syscall.Errno(result))
		}
	}
	return nil, errors.New("TCP owner table size unstable")
}

// processDescendsFrom reports whether child is ancestor or a descendant of
// ancestor. The walk is bounded so a malformed parent chain cannot loop, and
// every parent/child link is checked for creation-time plausibility through the
// kernel process identity: a parent must have started no later than its child
// (small tolerance for coarse clock resolution). Together these prevent a
// recycled or forged pid/parent pair from satisfying the ancestry check
// (FIND-WIN-020).
func processDescendsFrom(child, ancestor uint32) bool {
	if child == 0 || ancestor == 0 {
		return false
	}
	if child == ancestor {
		return true
	}
	parents, err := processParentMap()
	if err != nil {
		return false
	}
	parentOf := func(pid uint32) (uint32, bool) {
		parent, exists := parents[pid]
		return parent, exists
	}
	return descendsFromLineage(child, ancestor, parentOf, processCreationTime)
}

// processCreationTime returns the kernel creation timestamp of pid in Unix
// nanoseconds, or 0 when the process identity cannot be queried. A zero time is
// never treated as plausible by descendsFromLineage (fail-closed).
func processCreationTime(pid uint32) int64 {
	identity, err := winapi.OpenProcessIdentity(pid, false)
	if err != nil {
		return 0
	}
	created := identity.CreationUnixNano
	_ = identity.Close()
	return created
}

// descendsFromLineage is the pure ancestry walk. parentOf supplies the Toolhelp
// parent relation; creationOf supplies kernel creation times. A link whose
// timestamps are missing or reversed beyond the tolerance is rejected, as is a
// cycle or a chain longer than processLineageMaxDepth.
func descendsFromLineage(child, ancestor uint32, parentOf func(uint32) (uint32, bool), creationOf func(uint32) int64) bool {
	if child == 0 || ancestor == 0 {
		return false
	}
	if child == ancestor {
		return true
	}
	if parentOf == nil || creationOf == nil {
		return false
	}
	current := child
	visited := make(map[uint32]struct{}, processLineageMaxDepth)
	for depth := 0; depth < processLineageMaxDepth; depth++ {
		if _, seen := visited[current]; seen {
			return false
		}
		visited[current] = struct{}{}
		parent, exists := parentOf(current)
		if !exists || parent == 0 || parent == current {
			return false
		}
		childCreated := creationOf(current)
		parentCreated := creationOf(parent)
		if childCreated <= 0 || parentCreated <= 0 {
			return false
		}
		if parentCreated > childCreated+processCreationToleranceNanos {
			return false
		}
		if parent == ancestor {
			return true
		}
		current = parent
	}
	return false
}

func processParentMap() (map[uint32]uint32, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)
	parents := make(map[uint32]uint32, 256)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	seen := 0
	for {
		if entry.ProcessID != 0 {
			seen++
			if seen > maxProcessEntries {
				return nil, errors.New("process lineage boundary exceeded")
			}
			parents[entry.ProcessID] = entry.ParentProcessID
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return parents, nil
}
