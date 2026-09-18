// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"unsafe"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet                      uint32        = 2
	afInet6                     uint32        = 23
	tcpTableOwnerPIDConnections uint32        = 4
	errorInsufficientBuffer     syscall.Errno = 122
	maxTCPTableBytes                          = 16 << 20
	maxTCPRows                                = 131072
)

type TCPConnection struct {
	PID        uint32
	State      uint32
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
}

func TCPConnections() ([]TCPConnection, error) {
	ipv4, err := tcpTable(false)
	if err != nil {
		return nil, err
	}
	ipv6, err := tcpTable(true)
	if err != nil {
		return nil, err
	}
	if len(ipv4)+len(ipv6) > maxTCPRows {
		return nil, errors.New("TCP table row boundary exceeded")
	}
	return append(ipv4, ipv6...), nil
}

func tcpTable(ipv6 bool) ([]TCPConnection, error) {
	family := afInet
	rowSize := 24
	if ipv6 {
		family = afInet6
		rowSize = 56
	}
	var size uint32
	_, _, firstErr := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(tcpTableOwnerPIDConnections), 0)
	if size == 0 || int(size) > maxTCPTableBytes {
		if errnoResult(firstErr) != nil && !errors.Is(firstErr, errorInsufficientBuffer) {
			return nil, firstErr
		}
		return []TCPConnection{}, nil
	}
	buffer := make([]byte, size)
	result, _, callErr := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(tcpTableOwnerPIDConnections), 0)
	if result != 0 {
		if err := errnoResult(callErr); err != nil {
			return nil, err
		}
		return nil, syscall.Errno(result)
	}
	if len(buffer) < 4 {
		return nil, errors.New("TCP table response truncated")
	}
	rows := int(binary.LittleEndian.Uint32(buffer[:4]))
	if rows < 0 || rows > maxTCPRows || 4+rows*rowSize > len(buffer) {
		return nil, errors.New("TCP table response boundary rejected")
	}
	resultRows := make([]TCPConnection, 0, rows)
	for index := 0; index < rows; index++ {
		offset := 4 + index*rowSize
		row := buffer[offset : offset+rowSize]
		if ipv6 {
			connection, ok := parseTCP6Row(row)
			if ok {
				resultRows = append(resultRows, connection)
			}
		} else {
			connection, ok := parseTCP4Row(row)
			if ok {
				resultRows = append(resultRows, connection)
			}
		}
	}
	return resultRows, nil
}

func parseTCP4Row(row []byte) (TCPConnection, bool) {
	if len(row) != 24 {
		return TCPConnection{}, false
	}
	local := netip.AddrFrom4([4]byte{row[4], row[5], row[6], row[7]})
	remote := netip.AddrFrom4([4]byte{row[12], row[13], row[14], row[15]})
	return TCPConnection{
		State:      binary.LittleEndian.Uint32(row[0:4]),
		LocalAddr:  local,
		LocalPort:  binary.BigEndian.Uint16(row[8:10]),
		RemoteAddr: remote,
		RemotePort: binary.BigEndian.Uint16(row[16:18]),
		PID:        binary.LittleEndian.Uint32(row[20:24]),
	}, true
}

func parseTCP6Row(row []byte) (TCPConnection, bool) {
	if len(row) != 56 {
		return TCPConnection{}, false
	}
	var localBytes, remoteBytes [16]byte
	copy(localBytes[:], row[0:16])
	copy(remoteBytes[:], row[24:40])
	return TCPConnection{
		LocalAddr:  netip.AddrFrom16(localBytes),
		LocalPort:  binary.BigEndian.Uint16(row[20:22]),
		RemoteAddr: netip.AddrFrom16(remoteBytes),
		RemotePort: binary.BigEndian.Uint16(row[44:46]),
		State:      binary.LittleEndian.Uint32(row[48:52]),
		PID:        binary.LittleEndian.Uint32(row[52:56]),
	}, true
}
