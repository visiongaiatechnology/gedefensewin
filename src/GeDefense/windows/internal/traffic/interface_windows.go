//go:build windows

package traffic

import (
	"errors"
	"syscall"
	"unsafe"
)

var (
	modiphlpapi  = syscall.NewLazyDLL("iphlpapi.dll")
	getIfTable2  = modiphlpapi.NewProc("GetIfTable2")
	freeMibTable = modiphlpapi.NewProc("FreeMibTable")
	getIfTable   = modiphlpapi.NewProc("GetIfTable")
)

const (
	mibInterfaceNameChars = 256
	mibMaxPhysicalAddress = 8
	mibMaxDescription     = 256
	interfaceLoopback     = 24
	maxIfTableBytes       = 8 << 20
)

// MIB_IF_ROW2 from the Windows Netioapi / SDK. 64-bit native counters.
type mibIfRow2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               [16]byte
	Alias                       [257]uint16
	Description                 [257]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags byte
	Padding                     [3]byte
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 [16]byte
	ConnectionType              uint32
	Padding2                    [4]byte
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// MIB_IFROW from the Windows SDK for fallback.
type mibIfRow struct {
	Name            [mibInterfaceNameChars]uint16
	Index           uint32
	Type            uint32
	MTU             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [mibMaxPhysicalAddress]byte
	AdminStatus     uint32
	OperStatus      uint32
	LastChange      uint32
	InOctets        uint32
	InUcastPkts     uint32
	InNUcastPkts    uint32
	InDiscards      uint32
	InErrors        uint32
	InUnknownProtos uint32
	OutOctets       uint32
	OutUcastPkts    uint32
	OutNUcastPkts   uint32
	OutDiscards     uint32
	OutErrors       uint32
	OutQLen         uint32
	DescrLen        uint32
	Descr           [mibMaxDescription]byte
}

func ReadInterfaces() (map[uint32]Counters, error) {
	if getIfTable2.Find() == nil && freeMibTable.Find() == nil {
		rows, err := readInterfacesV2()
		if err == nil && len(rows) > 0 {
			return rows, nil
		}
	}
	return readInterfacesFallback()
}

func readInterfacesV2() (map[uint32]Counters, error) {
	var tablePtr unsafe.Pointer
	result, _, _ := getIfTable2.Call(uintptr(unsafe.Pointer(&tablePtr)))
	if result != 0 || tablePtr == nil {
		return nil, syscall.Errno(result)
	}
	defer func() {
		// FreeMibTable returns VOID; GetLastError is not defined for this API.
		_, _, _ = freeMibTable.Call(uintptr(tablePtr))
	}()

	count := *(*uint32)(tablePtr)
	if count == 0 || count > 4096 {
		return nil, errors.New("invalid network interface table count")
	}

	rowSize := unsafe.Sizeof(mibIfRow2{})
	firstRowOffset := uintptr(8)
	rows := make(map[uint32]Counters, count)

	for i := uintptr(0); i < uintptr(count); i++ {
		row := (*mibIfRow2)(unsafe.Pointer(uintptr(tablePtr) + firstRowOffset + i*rowSize))
		isFilter := (row.InterfaceAndOperStatusFlags & 2) != 0
		// OperStatus 1 = IfOperStatusUp
		if isFilter || row.Type == interfaceLoopback || row.OperStatus != 1 || row.InterfaceIndex == 0 {
			continue
		}
		rows[row.InterfaceIndex] = Counters{Rx: row.InOctets, Tx: row.OutOctets}
	}
	return rows, nil
}

func readInterfacesFallback() (map[uint32]Counters, error) {
	var size uint32
	result, _, _ := getIfTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if result != 0 && result != 122 {
		return nil, syscall.Errno(result)
	}
	if size < 4 || size > maxIfTableBytes {
		return nil, ErrUnavailable
	}
	buf := make([]byte, size)
	result, _, _ = getIfTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if result != 0 {
		return nil, syscall.Errno(result)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint64(unsafe.Sizeof(mibIfRow{}))
	if count > 4096 || uint64(4)+uint64(count)*rowSize > uint64(size) {
		return nil, errors.New("invalid network interface table boundary")
	}
	rows := make(map[uint32]Counters, count)
	for i := uint32(0); i < count; i++ {
		offset := 4 + uintptr(i)*uintptr(rowSize)
		row := (*mibIfRow)(unsafe.Pointer(&buf[offset]))
		// OperStatus in MIB_IFROW: 1 = MIB_IF_OPER_STATUS_UNREACHABLE / IfOperStatusUp, 5 = MIB_IF_OPER_STATUS_OPERATIONAL
		if row.Type == interfaceLoopback || (row.OperStatus != 1 && row.OperStatus != 5) || row.Index == 0 {
			continue
		}
		rows[row.Index] = Counters{Rx: uint64(row.InOctets), Tx: uint64(row.OutOctets)}
	}
	return rows, nil
}
