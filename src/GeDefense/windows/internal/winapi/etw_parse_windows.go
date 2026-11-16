// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	tdh = syscall.NewLazyDLL("tdh.dll")

	procTdhGetEventInformation = tdh.NewProc("TdhGetEventInformation")
	procTdhGetProperty         = tdh.NewProc("TdhGetProperty")
)

// Windows FileTime epoch (1601-01-01) to Unix epoch (1970-01-01) in 100ns ticks.
const filetimeUnixDelta int64 = 116444736000000000

func filetimeToUTC(ft int64) time.Time {
	if ft <= filetimeUnixDelta {
		return time.Time{}
	}
	ns := (ft - filetimeUnixDelta) * 100
	return time.Unix(0, ns).UTC()
}

// classifyETWEvent assigns a normalized provider name and event kind without
// trusting dynamic payload strings.
func classifyETWEvent(provider syscall.GUID, id uint16, opcode uint8) (providerName, kind string) {
	switch provider {
	case GUIDKernelProcess:
		providerName = "Kernel-Process"
		switch id {
		case 1:
			return providerName, "ProcessStart"
		case 2:
			return providerName, "ProcessStop"
		case 5:
			return providerName, "ImageLoad"
		default:
			return providerName, fmt.Sprintf("Event-%d", id)
		}
	case GUIDKernelFile:
		providerName = "Kernel-File"
		switch id {
		case 12:
			return providerName, "FileCreate"
		case 15:
			return providerName, "FileRename"
		case 26:
			return providerName, "FileDelete"
		default:
			return providerName, fmt.Sprintf("Event-%d", id)
		}
	case GUIDCodeIntegrity:
		providerName = "CodeIntegrity"
		switch id {
		case 3076:
			return providerName, "CodeIntegrityAudit"
		case 3077:
			return providerName, "CodeIntegrityBlock"
		default:
			return providerName, fmt.Sprintf("Event-%d", id)
		}
	default:
		return formatGUID(provider), fmt.Sprintf("Event-%d-Op%d", id, opcode)
	}
}

func formatGUID(g syscall.GUID) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// parseEventRecord translates a live EVENT_RECORD into an ETWEvent.
// If resolveProperties is true, TdhGetEventInformation extracts up to 16 scalar/string properties.
func parseEventRecord(rec *eventRecord, resolveProperties bool) (ETWEvent, error) {
	if rec == nil {
		return ETWEvent{}, errors.New("winapi etw: event record is nil")
	}
	provName, kind := classifyETWEvent(rec.EventHeader.ProviderId, rec.EventHeader.EventDescriptor.Id, rec.EventHeader.EventDescriptor.Opcode)
	ev := ETWEvent{
		ProviderGUID: rec.EventHeader.ProviderId,
		ProviderName: provName,
		Kind:         kind,
		EventID:      rec.EventHeader.EventDescriptor.Id,
		Opcode:       rec.EventHeader.EventDescriptor.Opcode,
		PID:          rec.EventHeader.ProcessId,
		TID:          rec.EventHeader.ThreadId,
		TimestampUTC: filetimeToUTC(rec.EventHeader.TimeStamp),
	}
	if resolveProperties && rec.UserDataLength > 0 && rec.UserData != 0 {
		props, err := readEventPropertiesTDH(rec)
		if err == nil && len(props) > 0 {
			ev.Properties = props
		}
	}
	return ev, nil
}

// parseSyntheticEventRecord parses a raw byte-encoded eventRecord header safely
// for pure unit tests without calling TDH or Windows trace sessions.
func parseSyntheticEventRecord(raw []byte) (ETWEvent, error) {
	minSize := int(unsafe.Sizeof(eventRecord{}))
	if len(raw) < minSize {
		return ETWEvent{}, fmt.Errorf("winapi etw: synthetic buffer %d bytes < %d", len(raw), minSize)
	}
	// Copy into an aligned buffer so unaligned caller slices remain safe.
	var rec eventRecord
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&rec)), minSize), raw[:minSize])
	return parseEventRecord(&rec, false)
}

func readEventPropertiesTDH(rec *eventRecord) (map[string]string, error) {
	var size uint32
	r1, _, _ := procTdhGetEventInformation.Call(
		uintptr(unsafe.Pointer(rec)), 0, 0, 0, uintptr(unsafe.Pointer(&size)),
	)
	if r1 != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) && r1 != 0 {
		return nil, syscall.Errno(r1)
	}
	if size == 0 || size > maxETWPropertiesBytes {
		return nil, fmt.Errorf("winapi etw: TDH metadata size %d out of bounds", size)
	}
	buf := make([]byte, size)
	r1, _, _ = procTdhGetEventInformation.Call(
		uintptr(unsafe.Pointer(rec)), 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
	)
	if r1 != 0 {
		return nil, syscall.Errno(r1)
	}
	if len(buf) < int(unsafe.Sizeof(traceEventInfoHeader{})) {
		return nil, errors.New("winapi etw: truncated TRACE_EVENT_INFO")
	}
	hdr := (*traceEventInfoHeader)(unsafe.Pointer(&buf[0]))
	count := int(hdr.TopLevelPropertyCount)
	if count <= 0 {
		return nil, nil
	}
	if count > 16 {
		count = 16
	}
	arrayOffset := 112 // offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) verified via MSVC
	propSize := int(unsafe.Sizeof(eventPropertyInfo{}))
	if arrayOffset+count*propSize > len(buf) {
		return nil, errors.New("winapi etw: property array exceeds metadata buffer")
	}

	out := make(map[string]string, count)
	for i := 0; i < count; i++ {
		prop := (*eventPropertyInfo)(unsafe.Pointer(&buf[arrayOffset+i*propSize]))
		name := readUTF16AtOffset(buf, int(prop.NameOffset))
		if name == "" {
			continue
		}
		if val, ok := readSingleTDHProperty(rec, buf, int(prop.NameOffset), prop.InType); ok {
			out[name] = val
		}
	}
	return out, nil
}

func readSingleTDHProperty(rec *eventRecord, meta []byte, nameOffset int, inType uint16) (string, bool) {
	if nameOffset <= 0 || nameOffset >= len(meta) {
		return "", false
	}
	desc := propertyDataDescriptor{
		PropertyName: uint64(uintptr(unsafe.Pointer(&meta[nameOffset]))),
		ArrayIndex:   0xFFFFFFFF,
	}
	var value [1024]byte
	r1, _, _ := procTdhGetProperty.Call(
		uintptr(unsafe.Pointer(rec)), 0, 0,
		1, uintptr(unsafe.Pointer(&desc)),
		uintptr(len(value)), uintptr(unsafe.Pointer(&value[0])),
	)
	if r1 != 0 {
		return "", false
	}
	return decodeTDHValue(inType, value[:]), true
}

func decodeTDHValue(inType uint16, buf []byte) string {
	switch inType {
	case tdhIntypeUnicodeString:
		return decodeBoundedUTF16Z(buf)
	case tdhIntypeAnsiString:
		if idx := strings.IndexByte(string(buf), 0); idx >= 0 {
			return strings.TrimSpace(string(buf[:idx]))
		}
		return strings.TrimSpace(string(buf))
	case tdhIntypeUInt16:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint16(buf[:2]))
	case tdhIntypeUInt32, tdhIntypeHexInt32:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint32(buf[:4]))
	case tdhIntypeUInt64, tdhIntypePointer, tdhIntypeSizeT, tdhIntypeHexInt64:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint64(buf[:8]))
	case tdhIntypeBoolean:
		if binary.LittleEndian.Uint32(buf[:4]) != 0 {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func readUTF16AtOffset(buf []byte, offset int) string {
	if offset <= 0 || offset >= len(buf)-1 {
		return ""
	}
	return decodeBoundedUTF16Z(buf[offset:])
}

func decodeBoundedUTF16Z(buf []byte) string {
	limit := len(buf) / 2
	if limit > maxETWNameChars {
		limit = maxETWNameChars
	}
	words := make([]uint16, 0, limit)
	for i := 0; i < limit; i++ {
		w := binary.LittleEndian.Uint16(buf[i*2 : i*2+2])
		if w == 0 {
			break
		}
		words = append(words, w)
	}
	return strings.TrimSpace(syscall.UTF16ToString(words))
}
