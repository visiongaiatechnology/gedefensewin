// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var procSetTcpEntry = iphlpapi.NewProc("SetTcpEntry")

// KillTCPConnections terminates active IPv4 TCP connections using
// iphlpapi.dll!SetTcpEntry with MIB_TCP_STATE_DELETE_TCB. Bounded to at most
// 4096 targets per call.
func KillTCPConnections(targets []TCPKillTarget) (int, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	if len(targets) > maxWFPKillTargets {
		return 0, fmt.Errorf("winapi tcp: target count %d exceeds %d", len(targets), maxWFPKillTargets)
	}
	killed := 0
	var firstErr error
	for _, target := range targets {
		row, err := buildDeleteTCBRow(target)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		r1, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&row)))
		if r1 != 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("winapi tcp SetTcpEntry: %w", syscall.Errno(r1))
			}
			continue
		}
		killed++
	}
	return killed, firstErr
}

func buildDeleteTCBRow(target TCPKillTarget) (mibTCPRow, error) {
	local := target.LocalIP.Unmap()
	remote := target.RemoteIP.Unmap()
	if !local.IsValid() || !local.Is4() || !remote.IsValid() || !remote.Is4() {
		return mibTCPRow{}, errors.New("winapi tcp: SetTcpEntry requires valid IPv4 addresses")
	}
	if target.LocalPort == 0 || target.RemotePort == 0 {
		return mibTCPRow{}, errors.New("winapi tcp: non-zero ports required")
	}
	l4 := local.As4()
	r4 := remote.As4()
	return mibTCPRow{
		State:      mibTCPStateDeleteTCB,
		LocalAddr:  binary.LittleEndian.Uint32(l4[:]),
		LocalPort:  uint32(htons(target.LocalPort)),
		RemoteAddr: binary.LittleEndian.Uint32(r4[:]),
		RemotePort: uint32(htons(target.RemotePort)),
	}, nil
}

func htons(v uint16) uint16 {
	return (v>>8)&0x00ff | (v&0x00ff)<<8
}
