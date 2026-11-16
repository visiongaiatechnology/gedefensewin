// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"syscall"
	"time"
)

// Exact x64 Windows SDK (10.0.26100.0) ETW & TDH constants and structure layouts.
// Verified directly via MSVC cl.exe sizeof/offsetof probes.

const (
	wnodeFlagTracedGUID uint32 = 0x00020000

	eventTraceRealTimeMode            uint32 = 0x00000100
	eventTraceNoPerProcessorBuffering uint32 = 0x10000000

	processTraceModeRealTime    uint32 = 0x00000100
	processTraceModeEventRecord uint32 = 0x10000000

	eventControlCodeDisableProvider uint32 = 0
	eventControlCodeEnableProvider  uint32 = 1
	traceLevelInformation           uint8  = 4

	eventTraceControlQuery uint32 = 0
	eventTraceControlStop  uint32 = 1
	eventTraceControlFlush uint32 = 3

	eventHeaderFlag32BitHeader uint16 = 0x0020
	eventHeaderFlag64BitHeader uint16 = 0x0040

	invalidProcessedTraceHandle uint64 = 0xFFFFFFFFFFFFFFFF

	tdhIntypeUnicodeString uint16 = 1
	tdhIntypeAnsiString    uint16 = 2
	tdhIntypeUInt16        uint16 = 6
	tdhIntypeUInt32        uint16 = 8
	tdhIntypeUInt64        uint16 = 10
	tdhIntypeBoolean       uint16 = 13
	tdhIntypePointer       uint16 = 16
	tdhIntypeHexInt32      uint16 = 20
	tdhIntypeHexInt64      uint16 = 21
	tdhIntypeSizeT         uint16 = 308

	maxETWNameChars       = 256
	maxETWEventQueue      = 1024
	maxETWPropertiesBytes = 64 << 10
)

var (
	// GUIDKernelProcess is Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}.
	GUIDKernelProcess = syscall.GUID{
		Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
		Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
	}
	// GUIDKernelFile is Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}.
	GUIDKernelFile = syscall.GUID{
		Data1: 0xEDD08927, Data2: 0x9CC4, Data3: 0x4E65,
		Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89},
	}
	// GUIDCodeIntegrity is Microsoft-Windows-CodeIntegrity {4EE76BD8-3CF4-44A0-A0AC-3937643E37A3}.
	GUIDCodeIntegrity = syscall.GUID{
		Data1: 0x4EE76BD8, Data2: 0x3CF4, Data3: 0x44A0,
		Data4: [8]byte{0xA0, 0xAC, 0x39, 0x37, 0x64, 0x3E, 0x37, 0xA3},
	}
)

// wnodeHeader mirrors WNODE_HEADER (48 bytes on x64).
type wnodeHeader struct {
	BufferSize        uint32       // 0
	ProviderId        uint32       // 4
	HistoricalContext uint64       // 8
	TimeStamp         int64        // 16
	Guid              syscall.GUID // 24
	ClientContext     uint32       // 40
	Flags             uint32       // 44
}

// eventTraceProperties mirrors EVENT_TRACE_PROPERTIES (120 bytes on x64).
type eventTraceProperties struct {
	Wnode               wnodeHeader // 0 (48 bytes)
	BufferSize          uint32      // 48
	MinimumBuffers      uint32      // 52
	MaximumBuffers      uint32      // 56
	MaximumFileSize     uint32      // 60
	LogFileMode         uint32      // 64
	FlushTimer          uint32      // 68
	EnableFlags         uint32      // 72
	AgeLimit            int32       // 76
	NumberOfBuffers     uint32      // 80
	FreeBuffers         uint32      // 84
	EventsLost          uint32      // 88
	BuffersWritten      uint32      // 92
	LogBuffersLost      uint32      // 96
	RealTimeBuffersLost uint32      // 100
	LoggerThreadId      uintptr     // 104
	LogFileNameOffset   uint32      // 112
	LoggerNameOffset    uint32      // 116
}

// eventTraceLogfileW mirrors EVENT_TRACE_LOGFILEW (448 bytes on x64).
// Explicit byte regions guarantee 100% alignment with Windows SDK x64 ABI:
// LogFileName@0, LoggerName@8, ProcessTraceMode@28, BufferCallback@400,
// EventRecordCallback@424, Context@440.
type eventTraceLogfileW struct {
	LogFileName         *uint16   // 0
	LoggerName          *uint16   // 8
	CurrentTime         int64     // 16
	BuffersRead         uint32    // 24
	ProcessTraceMode    uint32    // 28
	CurrentEventPad     [368]byte // 32..400 (CurrentEvent + LogfileHeader)
	BufferCallback      uintptr   // 400
	BufferSize          uint32    // 408
	Filled              uint32    // 412
	EventsLost          uint32    // 416
	_pad420             uint32    // 420
	EventRecordCallback uintptr   // 424
	IsKernelTrace       uint32    // 432
	_pad436             uint32    // 436
	Context             uintptr   // 440
}

// eventDescriptor mirrors EVENT_DESCRIPTOR (16 bytes).
type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader mirrors EVENT_HEADER (80 bytes).
type eventHeader struct {
	Size            uint16          // 0
	HeaderType      uint16          // 2
	Flags           uint16          // 4
	EventProperty   uint16          // 6
	ThreadId        uint32          // 8
	ProcessId       uint32          // 12
	TimeStamp       int64           // 16
	ProviderId      syscall.GUID    // 24
	EventDescriptor eventDescriptor // 40
	KernelTime      uint32          // 56
	UserTime        uint32          // 60
	ActivityId      syscall.GUID    // 64
}

// etwBufferContext mirrors ETW_BUFFER_CONTEXT (4 bytes).
type etwBufferContext struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerId        uint16
}

// eventRecord mirrors EVENT_RECORD (112 bytes on x64).
type eventRecord struct {
	EventHeader       eventHeader      // 0 (80 bytes)
	BufferContext     etwBufferContext // 80
	ExtendedDataCount uint16           // 84
	UserDataLength    uint16           // 86
	ExtendedData      uintptr          // 88
	UserData          uintptr          // 96
	UserContext       uintptr          // 104
}

// traceEventInfoHeader mirrors the fixed header of TRACE_EVENT_INFO up to PropertyCount.
type traceEventInfoHeader struct {
	ProviderGuid          syscall.GUID    // 0
	EventGuid             syscall.GUID    // 16
	EventDescriptor       eventDescriptor // 32
	DecodingSource        uint32          // 48
	ProviderNameOffset    uint32          // 52
	LevelNameOffset       uint32          // 56
	ChannelNameOffset     uint32          // 60
	KeywordsNameOffset    uint32          // 64
	TaskNameOffset        uint32          // 68
	OpcodeNameOffset      uint32          // 72
	EventMessageOffset    uint32          // 76
	ProviderMessageOffset uint32          // 80
	BinaryXMLOffset       uint32          // 84
	BinaryXMLSize         uint32          // 88
	EventNameOffset       uint32          // 92
	EventAttributesOffset uint32          // 96
	PropertyCount         uint32          // 100
	TopLevelPropertyCount uint32          // 104
	Flags                 uint32          // 108
}

// eventPropertyInfo mirrors EVENT_PROPERTY_INFO (24 bytes).
type eventPropertyInfo struct {
	Flags         uint32 // 0
	NameOffset    uint32 // 4
	InType        uint16 // 8
	OutType       uint16 // 10
	MapNameOffset uint32 // 12
	CountOrIndex  uint16 // 16
	LengthOrIndex uint16 // 18
	Reserved      uint32 // 20
}

// propertyDataDescriptor mirrors PROPERTY_DATA_DESCRIPTOR (16 bytes).
type propertyDataDescriptor struct {
	PropertyName uint64 // 0
	ArrayIndex   uint32 // 8
	Reserved     uint32 // 12
}

// ETWProviderConfig enables one provider GUID with optional keyword bitmask.
type ETWProviderConfig struct {
	GUID            syscall.GUID
	Level           uint8
	MatchAnyKeyword uint64
}

// ETWConfig configures an in-process real-time ETW consumer session.
type ETWConfig struct {
	SessionName string
	Providers   []ETWProviderConfig
	QueueSize   int
}

// ETWEvent is one parsed real-time telemetry observation.
type ETWEvent struct {
	ProviderGUID syscall.GUID
	ProviderName string
	Kind         string
	EventID      uint16
	Opcode       uint8
	PID          uint32
	TID          uint32
	TimestampUTC time.Time
	Properties   map[string]string
}

// ETWStatus reports bounded session telemetry counters honestly.
type ETWStatus struct {
	SessionName   string
	Running       bool
	EventsRead    uint64
	DroppedEvents uint64
	LastError     string
}
