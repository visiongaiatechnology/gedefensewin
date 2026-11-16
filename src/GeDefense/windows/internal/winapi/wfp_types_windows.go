// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"net/netip"
	"syscall"
)

// Exact x64 Windows SDK (10.0.26100.0) Windows Filtering Platform (WFP) and
// iphlpapi MIB_TCPROW constants & structures verified via MSVC cl.exe.

const (
	rpcCAuthnDefault uint32 = 0xFFFFFFFF

	fwpmSessionFlagDynamic uint32 = 0x00000001
	fwpmFilterFlagNone     uint32 = 0x00000000

	fwpActionBlock  uint32 = 0x00001001
	fwpActionPermit uint32 = 0x00001002

	fwpMatchEqual    uint32 = 0
	fwpMatchNotEqual uint32 = 10

	fwpEmpty        uint32 = 0
	fwpUInt8        uint32 = 1
	fwpUInt16       uint32 = 2
	fwpUInt32       uint32 = 3
	fwpUInt64       uint32 = 4
	fwpByteBlobType uint32 = 12
	fwpV4AddrMask   uint32 = 256
	fwpV6AddrMask   uint32 = 257

	mibTCPStateDeleteTCB uint32 = 12
	maxWFPFilters               = 256
	maxWFPKillTargets           = 4096
)

var (
	// FWPMLayerALEAuthConnectV4 {c38d57d1-05a7-4c33-904f-7fbceee60e82}.
	FWPMLayerALEAuthConnectV4 = syscall.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	// FWPMLayerALEAuthConnectV6 {4a72393b-319f-44bc-84c3-ba54dcb3b6b4}.
	FWPMLayerALEAuthConnectV6 = syscall.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	// FWPMLayerALEAuthRecvAcceptV4 {e1cd9fe7-f4b5-4273-96c0-592e487b8650}.
	FWPMLayerALEAuthRecvAcceptV4 = syscall.GUID{
		Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
	}
	// FWPMLayerALEAuthRecvAcceptV6 {a3b42c97-9f04-4672-b87e-cee9c483257f}.
	FWPMLayerALEAuthRecvAcceptV6 = syscall.GUID{
		Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
	}

	// FWPMConditionIPRemoteAddress {b235ae9a-1d64-49b8-a44c-5ff3d9095045}.
	FWPMConditionIPRemoteAddress = syscall.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
	// FWPMConditionIPRemotePort {c35a604d-d22b-4e1a-91b4-68f674ee674b}.
	FWPMConditionIPRemotePort = syscall.GUID{
		Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
	// FWPMConditionIPProtocol {3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}.
	FWPMConditionIPProtocol = syscall.GUID{
		Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
	// FWPMConditionALEAppID {d78e1e87-8644-4ea5-9437-d809ecefc971}.
	FWPMConditionALEAppID = syscall.GUID{
		Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
	}

	// guidGeDefenseWFPSublayer is the deterministic sublayer owned by GeDefense V6.
	guidGeDefenseWFPSublayer = syscall.GUID{
		Data1: 0x9b2f7c14, Data2: 0x61a3, Data3: 0x4d88,
		Data4: [8]byte{0x91, 0x0b, 0x56, 0x47, 0x45, 0x36, 0x00, 0x01},
	}
)

type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

type fwpmSession0 struct {
	SessionKey           syscall.GUID     // 0
	DisplayData          fwpmDisplayData0 // 16
	Flags                uint32           // 32
	TxnWaitTimeoutInMSec uint32           // 36
	ProcessId            uint32           // 40
	_pad44               uint32           // 44
	Sid                  uintptr          // 48
	Username             *uint16          // 56
	KernelMode           uint32           // 64
	_pad68               uint32           // 68
}

type fwpByteBlob struct {
	Size uint32
	_pad uint32
	Data uintptr
}

type fwpmSublayer0 struct {
	SubLayerKey  syscall.GUID     // 0
	DisplayData  fwpmDisplayData0 // 16
	Flags        uint32           // 32
	_pad36       uint32           // 36
	ProviderKey  *syscall.GUID    // 40
	ProviderData fwpByteBlob      // 48
	Weight       uint16           // 64
	_pad66       [6]byte          // 66
}

type fwpValue0 struct {
	Type  uint32
	_pad4 uint32
	Value uint64
}

type fwpConditionValue0 struct {
	Type  uint32
	_pad4 uint32
	Value uint64
}

type fwpmFilterCondition0 struct {
	FieldKey       syscall.GUID       // 0
	MatchType      uint32             // 16
	_pad20         uint32             // 20
	ConditionValue fwpConditionValue0 // 24
}

type fwpmAction0 struct {
	Type       uint32       // 0
	FilterType syscall.GUID // 4
}

type fwpmFilter0 struct {
	FilterKey           syscall.GUID          // 0
	DisplayData         fwpmDisplayData0      // 16
	Flags               uint32                // 32
	_pad36              uint32                // 36
	ProviderKey         *syscall.GUID         // 40
	ProviderData        fwpByteBlob           // 48
	LayerKey            syscall.GUID          // 64
	SubLayerKey         syscall.GUID          // 80
	Weight              fwpValue0             // 96
	NumFilterConditions uint32                // 112
	_pad116             uint32                // 116
	FilterCondition     *fwpmFilterCondition0 // 120
	Action              fwpmAction0           // 128
	_pad148             uint32                // 148
	ProviderContextKey  syscall.GUID          // 152
	Reserved            uintptr               // 168
	FilterId            uint64                // 176
	EffectiveWeight     fwpValue0             // 184
}

type fwpV4AddrAndMask struct {
	Addr uint32
	Mask uint32
}

type fwpV6AddrAndMask struct {
	Addr         [16]byte
	PrefixLength uint8
}

// WFPRuleSpec describes one validated filter in a policy plan.
type WFPRuleSpec struct {
	Name      string
	LayerGUID syscall.GUID
	Action    uint32
	Weight    uint8
	Prefix    netip.Prefix
	Port      uint16
	Protocol  uint8
	AppPath   string
}

// WFPConfig configures native Windows Filtering Platform sovereign policies.
type WFPConfig struct {
	DryRun             bool
	BlockMetadata      bool
	PinDNSToResolvers  bool
	AllowedDNSServers  []netip.Addr
	BlockAppPaths      []string
	ExtraBlockPrefixes []netip.Prefix
}

// WFPStatus reports the applied/planned WFP filter state honestly.
type WFPStatus struct {
	DryRun       bool
	Active       bool
	FilterIDs    []uint64
	PlannedRules int
	LastError    string
}

// TCPKillTarget identifies an established IPv4 TCP tuple to terminate via SetTcpEntry.
type TCPKillTarget struct {
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
}
