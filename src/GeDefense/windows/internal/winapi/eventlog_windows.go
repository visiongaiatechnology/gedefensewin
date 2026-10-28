// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// Native Windows Event Log pull-subscription bridge. The GeDefense sensors use
// wevtapi.dll directly instead of a long-lived powershell.exe child process:
// one subscription handle, one unnamed signal event, bounded EvtNext batches
// and bounded EvtRender buffers. Every handle is closed on every exit path.
//
// The allowlist is intentionally closed: only the two channels the product
// ships sensors for may be subscribed. Callers cannot open arbitrary channels,
// so a compromised configuration path cannot turn this bridge into a generic
// Security log reader.
const (
	eventLogBatchSize        = 64
	eventLogRecordBufferSize = 16
	eventLogWaitMilliseconds = 1000
	maximumEventXMLBytes     = 1 << 20
	maximumEventLogXPathLen  = 4096
	maximumEventLogChannel   = 256
	maximumEventLogEventIDs  = 32
	maximumEventLogIDValue   = 65535

	evtSubscribeToFutureEvents      = 1
	evtSubscribeStartAtOldestRecord = 2
	evtRenderEventXML               = 1

	errorEventLogNoMoreItems syscall.Errno = 259
	errorEventLogTimeout     syscall.Errno = 1460
)

var (
	wevtapi = syscall.NewLazyDLL("wevtapi.dll")

	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtNext      = wevtapi.NewProc("EvtNext")
	procEvtRender    = wevtapi.NewProc("EvtRender")
	procEvtClose     = wevtapi.NewProc("EvtClose")
	procResetEvent   = kernel32.NewProc("ResetEvent")
)

// EventLogRecord is one rendered Windows Event Log record. XML is the UTF-8
// EvtRenderEventXml document; TimeCreated is the System/TimeCreated value and
// RecordID the System/EventRecordID cursor.
type EventLogRecord struct {
	RecordID    int64
	Channel     string
	XML         []byte
	TimeCreated time.Time
}

// eventLogChannelAllowlist maps the case-folded public channel name to the
// canonical channel path used by wevtapi.
var eventLogChannelAllowlist = map[string]string{
	"security": "Security",
	"microsoft-windows-windows defender/operational": "Microsoft-Windows-Windows Defender/Operational",
}

// StreamEventLog opens a native wevtapi pull subscription and streams rendered
// records. The records channel is buffered and always closed when the stream
// ends; the error channel is buffered with capacity one and carries at most one
// fatal error before both channels are closed. A plain context cancellation
// closes the channels without reporting a fault. Subscription and query
// rejection are returned synchronously and never start a goroutine.
//
// startAfterRecordID > 0 selects replay: the subscription starts at the oldest
// matching record and xpath must restrict itself with an EventRecordID filter
// (EventLogXPath provides it); records at or below the cursor are additionally
// suppressed here so a cursor contract cannot be violated by a caller query.
// startAfterRecordID <= 0 selects future events only.
func StreamEventLog(ctx context.Context, channel, xpath string, startAfterRecordID int64) (<-chan EventLogRecord, <-chan error, error) {
	if ctx == nil {
		return nil, nil, errors.New("event log context required")
	}
	canonical, err := canonicalEventLogChannel(channel)
	if err != nil {
		return nil, nil, err
	}
	query, origin, err := prepareEventLogQuery(xpath, startAfterRecordID)
	if err != nil {
		return nil, nil, err
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	return openEventLogStream(ctx, canonical, query, origin, startAfterRecordID)
}

// EventLogXPath builds the XPath query for a bounded set of event IDs. Event
// IDs are validated, deduplicated and sorted; a positive startAfterRecordID
// adds the EventRecordID replay filter so a restarted sensor resumes at its
// last committed cursor instead of replaying the whole channel.
func EventLogXPath(eventIDs []int, startAfterRecordID int64) (string, error) {
	if len(eventIDs) == 0 || len(eventIDs) > maximumEventLogEventIDs {
		return "", errors.New("event log event id boundary rejected")
	}
	unique := make(map[int]struct{}, len(eventIDs))
	ids := make([]int, 0, len(eventIDs))
	for _, id := range eventIDs {
		if id <= 0 || id > maximumEventLogIDValue {
			return "", errors.New("event log event id rejected")
		}
		if _, seen := unique[id]; seen {
			continue
		}
		unique[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var selector strings.Builder
	if len(ids) == 1 {
		fmt.Fprintf(&selector, "EventID=%d", ids[0])
	} else {
		selector.WriteByte('(')
		for index, id := range ids {
			if index > 0 {
				selector.WriteString(" or ")
			}
			fmt.Fprintf(&selector, "EventID=%d", id)
		}
		selector.WriteByte(')')
	}
	if startAfterRecordID > 0 {
		fmt.Fprintf(&selector, " and EventRecordID > %d", startAfterRecordID)
	}
	query := "*[System[" + selector.String() + "]]"
	if len(query) > maximumEventLogXPathLen {
		return "", errors.New("event log xpath length rejected")
	}
	return query, nil
}

func canonicalEventLogChannel(channel string) (string, error) {
	if channel == "" || len(channel) > maximumEventLogChannel || strings.IndexByte(channel, 0) >= 0 {
		return "", errors.New("event log channel rejected")
	}
	canonical, ok := eventLogChannelAllowlist[strings.ToLower(channel)]
	if !ok {
		return "", errors.New("event log channel is not allowlisted")
	}
	return canonical, nil
}

func validateEventLogXPath(xpath string) error {
	if xpath == "" || len(xpath) > maximumEventLogXPathLen {
		return errors.New("event log xpath boundary rejected")
	}
	if !utf8.ValidString(xpath) {
		return errors.New("event log xpath encoding rejected")
	}
	for _, character := range xpath {
		if character < 0x20 || character == 0x7f {
			return errors.New("event log xpath contains control characters")
		}
	}
	return nil
}

// prepareEventLogQuery validates the caller query and selects the subscription
// origin. Replay without an EventRecordID filter is rejected: silently starting
// at the oldest record without a cursor would replay and re-deliver history.
func prepareEventLogQuery(xpath string, startAfterRecordID int64) (string, uint32, error) {
	query := xpath
	if query == "" {
		query = "*"
	}
	if err := validateEventLogXPath(query); err != nil {
		return "", 0, err
	}
	if startAfterRecordID > 0 {
		if !strings.Contains(strings.ToLower(query), "eventrecordid") {
			if query != "*" {
				return "", 0, errors.New("event log replay xpath requires an EventRecordID filter")
			}
			query = fmt.Sprintf("*[System[EventRecordID > %d]]", startAfterRecordID)
			if err := validateEventLogXPath(query); err != nil {
				return "", 0, err
			}
		}
		return query, evtSubscribeStartAtOldestRecord, nil
	}
	return query, evtSubscribeToFutureEvents, nil
}

// eventLogStream owns the subscription handle, the signal event and the single
// streaming goroutine. Handles are created synchronously so a rejected
// subscription is reported to the caller instead of a background goroutine.
type eventLogStream struct {
	channel      string
	subscription syscall.Handle
	signal       Handle
}

func openEventLogStream(ctx context.Context, channel, query string, origin uint32, startAfterRecordID int64) (<-chan EventLogRecord, <-chan error, error) {
	signal, _, eventErr := CreateEvent("", false, false)
	if eventErr != nil || signal == 0 {
		if eventErr != nil {
			return nil, nil, fmt.Errorf("event log signal event rejected: %w", eventErr)
		}
		return nil, nil, errors.New("event log signal event rejected")
	}
	closeSignal := func() {
		_ = CloseHandle(signal)
	}
	channelPointer, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		closeSignal()
		return nil, nil, fmt.Errorf("event log channel encoding rejected: %w", err)
	}
	queryPointer, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		closeSignal()
		return nil, nil, fmt.Errorf("event log xpath encoding rejected: %w", err)
	}
	subscription, _, callErr := procEvtSubscribe.Call(
		0,
		uintptr(signal),
		uintptr(unsafe.Pointer(channelPointer)),
		uintptr(unsafe.Pointer(queryPointer)),
		0,
		0,
		0,
		uintptr(origin),
	)
	if subscription == 0 {
		closeSignal()
		if err := errnoResult(callErr); err != nil {
			return nil, nil, fmt.Errorf("event log subscription rejected: %w", err)
		}
		return nil, nil, errors.New("event log subscription rejected")
	}
	stream := &eventLogStream{channel: channel, subscription: syscall.Handle(subscription), signal: signal}
	records := make(chan EventLogRecord, eventLogRecordBufferSize)
	faults := make(chan error, 1)
	go stream.run(ctx, records, faults, startAfterRecordID)
	return records, faults, nil
}

// run is the only goroutine that touches the subscription. It reports at most
// one fatal error, then releases every native handle and closes both channels.
// The records channel is closed before the error channel so a consumer that
// observes the closed records channel can read the buffered fatal error.
func (s *eventLogStream) run(ctx context.Context, records chan<- EventLogRecord, faults chan<- error, startAfterRecordID int64) {
	fatal := s.stream(ctx, records, startAfterRecordID)
	if fatal != nil && ctx.Err() == nil {
		select {
		case faults <- fatal:
		default:
		}
	}
	s.close()
	close(records)
	close(faults)
}

func (s *eventLogStream) stream(ctx context.Context, records chan<- EventLogRecord, startAfterRecordID int64) error {
	if err := s.drain(ctx, records, startAfterRecordID); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		result, err := WaitForSingleObject(s.signal, eventLogWaitMilliseconds)
		if err != nil {
			return fmt.Errorf("event log wait failed: %w", err)
		}
		switch result {
		case WaitObject0:
			if err := resetEvent(s.signal); err != nil {
				return fmt.Errorf("event log signal reset failed: %w", err)
			}
			if err := s.drain(ctx, records, startAfterRecordID); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		case syscall.WAIT_TIMEOUT:
			continue
		default:
			return fmt.Errorf("event log wait returned status %d", result)
		}
	}
}

// drain consumes bounded EvtNext batches until the subscription reports no more
// available records. EvtNext runs with a bounded timeout instead of zero so a
// blocking native call can never outlive a context cancellation by more than
// one wait slice. Records at or below the replay cursor are suppressed.
func (s *eventLogStream) drain(ctx context.Context, records chan<- EventLogRecord, startAfterRecordID int64) error {
	handles := make([]syscall.Handle, eventLogBatchSize)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var returned uint32
		result, _, callErr := procEvtNext.Call(
			uintptr(s.subscription),
			uintptr(len(handles)),
			uintptr(unsafe.Pointer(&handles[0])),
			uintptr(eventLogWaitMilliseconds),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if result == 0 {
			if errors.Is(callErr, errorEventLogNoMoreItems) || errors.Is(callErr, errorEventLogTimeout) {
				return nil
			}
			if err := errnoResult(callErr); err != nil {
				return fmt.Errorf("event log read failed: %w", err)
			}
			return errors.New("event log read failed")
		}
		if returned == 0 {
			return nil
		}
		if returned > uint32(len(handles)) {
			closeEventLogHandles(handles, 0, uint32(len(handles)))
			return errors.New("event log batch boundary rejected")
		}
		for index := uint32(0); index < returned; index++ {
			handle := handles[index]
			handles[index] = 0
			record, renderErr := renderEventLogRecord(handle, s.channel)
			closeErr := closeEventLogHandle(handle)
			if renderErr != nil {
				closeEventLogHandles(handles, index+1, returned)
				return renderErr
			}
			if closeErr != nil {
				closeEventLogHandles(handles, index+1, returned)
				return closeErr
			}
			if startAfterRecordID > 0 && record.RecordID <= startAfterRecordID {
				continue
			}
			select {
			case records <- record:
			case <-ctx.Done():
				closeEventLogHandles(handles, index+1, returned)
				return ctx.Err()
			}
		}
	}
}

func (s *eventLogStream) close() {
	if s == nil {
		return
	}
	if s.subscription != 0 {
		_, _, _ = procEvtClose.Call(uintptr(s.subscription))
		s.subscription = 0
	}
	if s.signal != 0 {
		_ = CloseHandle(s.signal)
		s.signal = 0
	}
}

func resetEvent(handle Handle) error {
	result, _, callErr := procResetEvent.Call(uintptr(handle))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("ResetEvent failed")
	}
	return nil
}

func closeEventLogHandle(handle syscall.Handle) error {
	if handle == 0 {
		return nil
	}
	result, _, callErr := procEvtClose.Call(uintptr(handle))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return fmt.Errorf("event log handle close failed: %w", err)
		}
		return errors.New("event log handle close failed")
	}
	return nil
}

func closeEventLogHandles(handles []syscall.Handle, from, to uint32) {
	for index := from; index < to && index < uint32(len(handles)); index++ {
		if handles[index] != 0 {
			_, _, _ = procEvtClose.Call(uintptr(handles[index]))
			handles[index] = 0
		}
	}
}

// renderEventLogRecord queries the required buffer size first, enforces the
// 1 MiB per-event cap and renders the record as UTF-8 XML.
func renderEventLogRecord(handle syscall.Handle, channel string) (EventLogRecord, error) {
	var used, propertyCount uint32
	result, _, callErr := procEvtRender.Call(
		0,
		uintptr(handle),
		evtRenderEventXML,
		0,
		0,
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if result == 0 && !errors.Is(callErr, errorInsufficientBuffer) {
		if err := errnoResult(callErr); err != nil {
			return EventLogRecord{}, fmt.Errorf("event log render sizing failed: %w", err)
		}
		return EventLogRecord{}, errors.New("event log render sizing failed")
	}
	if used == 0 || used > maximumEventXMLBytes {
		return EventLogRecord{}, errors.New("event log render size rejected")
	}
	buffer := make([]byte, used)
	var rendered, renderedProperties uint32
	result, _, callErr = procEvtRender.Call(
		0,
		uintptr(handle),
		evtRenderEventXML,
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&rendered)),
		uintptr(unsafe.Pointer(&renderedProperties)),
	)
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return EventLogRecord{}, fmt.Errorf("event log render failed: %w", err)
		}
		return EventLogRecord{}, errors.New("event log render failed")
	}
	if rendered == 0 || rendered > uint32(len(buffer)) {
		return EventLogRecord{}, errors.New("event log render boundary rejected")
	}
	text, err := decodeEventLogUTF16LE(buffer[:rendered])
	if err != nil {
		return EventLogRecord{}, err
	}
	return parseEventLogRecordXML(channel, []byte(text))
}

// decodeEventLogUTF16LE converts the EvtRender UTF-16LE byte buffer into a Go
// (UTF-8) string. A UTF-16 BOM is stripped, the string is truncated at the NUL
// terminator and empty payloads are rejected.
func decodeEventLogUTF16LE(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return "", errors.New("event log utf-16 boundary rejected")
	}
	units := make([]uint16, len(raw)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(raw[index*2:])
	}
	if len(units) > 0 && units[0] == 0xFEFF {
		units = units[1:]
	}
	for index, unit := range units {
		if unit == 0 {
			units = units[:index]
			break
		}
	}
	if len(units) == 0 {
		return "", errors.New("event log xml rejected")
	}
	text := string(utf16.Decode(units))
	if strings.TrimSpace(text) == "" {
		return "", errors.New("event log xml rejected")
	}
	return text, nil
}

type renderedEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventRecordID int64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
}

// parseEventLogRecordXML extracts the cursor and event timestamp from the XML
// rendered by EvtRender. A missing EventRecordID is a record-integrity failure;
// a missing or malformed SystemTime falls back to receipt time, never to the
// zero time.
func parseEventLogRecordXML(channel string, rendered []byte) (EventLogRecord, error) {
	if len(rendered) == 0 || len(rendered) > 2*maximumEventXMLBytes {
		return EventLogRecord{}, errors.New("event log xml size rejected")
	}
	var document renderedEventXML
	if err := xml.Unmarshal(rendered, &document); err != nil {
		return EventLogRecord{}, errors.New("event log xml rejected")
	}
	if document.System.EventRecordID <= 0 {
		return EventLogRecord{}, errors.New("event log record id rejected")
	}
	created := time.Now().UTC()
	if value := strings.TrimSpace(document.System.TimeCreated.SystemTime); value != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			created = parsed.UTC()
		}
	}
	return EventLogRecord{
		RecordID:    document.System.EventRecordID,
		Channel:     channel,
		XML:         append([]byte(nil), rendered...),
		TimeCreated: created,
	}, nil
}
