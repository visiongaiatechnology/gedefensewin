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
)

// The browser bootstrap is bound to the exact process the Center launched, so
// no session secret has to travel through a Chromium command line
// (AN-FIND-002 / UI-FIND-004). This file resolves a loopback peer address to
// the owning process id via the Windows TCP owner table and validates process
// ancestry via a Toolhelp snapshot. Both calls are read-only and need no
// elevation for processes of the same user.

const tcpTableOwnerPIDAll = 5

var (
	modIPHlpAPI              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCPTable  = modIPHlpAPI.NewProc("GetExtendedTcpTable")
	errPeerLookupUnavailable = errors.New("peer process lookup unavailable")
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
	if len(table) < 4 {
		return 0, errors.New("truncated TCP owner table")
	}
	rows := binary.LittleEndian.Uint32(table[:4])
	const rowSize = 24
	if int64(len(table)) < int64(4)+int64(rows)*rowSize {
		return 0, errors.New("truncated TCP owner table")
	}
	for index := uint32(0); index < rows; index++ {
		offset := 4 + int(index)*rowSize
		row := table[offset : offset+rowSize]
		// The client socket row is the mirror of the accepted server socket:
		// local port = server's view of the client port, remote endpoint = the
		// control plane listener.
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
	if len(table) < 4 || len(remoteServerAddr) != 16 {
		return 0, errors.New("truncated TCP owner table")
	}
	rows := binary.LittleEndian.Uint32(table[:4])
	const rowSize = 56
	if int64(len(table)) < int64(4)+int64(rows)*rowSize {
		return 0, errors.New("truncated TCP owner table")
	}
	for index := uint32(0); index < rows; index++ {
		offset := 4 + int(index)*rowSize
		row := table[offset : offset+rowSize]
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
// ancestor. The walk is bounded so a malformed parent chain cannot loop.
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
	current := child
	for depth := 0; depth < 8; depth++ {
		parent, exists := parents[current]
		if !exists || parent == 0 || parent == current {
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
	for {
		if entry.ProcessID != 0 {
			parents[entry.ProcessID] = entry.ParentProcessID
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return parents, nil
}
