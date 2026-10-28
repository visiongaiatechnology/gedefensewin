// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const defenderDetectionEventXML = `<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Windows Defender" Guid="{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}"/>
    <EventID>1116</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-25T10:00:00.1234567Z"/>
    <EventRecordID>4242</EventRecordID>
    <Correlation/>
    <Execution ProcessID="4" ThreadID="8"/>
    <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
    <Computer>VGT-TESTHOST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="Product Name">Microsoft Defender Antivirus</Data>
    <Data Name="Threat Name">Trojan:Win32/VgtFixture</Data>
    <Data Name="Severity Name">Schwerwiegend</Data>
    <Data Name="Path">C:\Users\Test\evil.exe</Data>
    <Data Name="Detection User">VGT-TESTHOST\operator</Data>
  </EventData>
</Event>`

func defenderFixtureRecord(xml string) winapi.EventLogRecord {
	return winapi.EventLogRecord{
		RecordID:    4242,
		Channel:     defenderOperationalChannel,
		XML:         []byte(xml),
		TimeCreated: time.Date(2026, 10, 25, 10, 0, 0, 123456700, time.UTC),
	}
}

func TestParseDefenderRecordPreservesContract(t *testing.T) {
	event, err := parseDefenderRecord(defenderFixtureRecord(defenderDetectionEventXML))
	if err != nil {
		t.Fatalf("rejected Defender detection: %v", err)
	}
	if event.EventID != 1116 || event.RecordID != 4242 {
		t.Fatalf("event identity changed: %+v", event)
	}
	if event.TimestampUTC != "2026-10-25T10:00:00.1234567Z" {
		t.Fatalf("event timestamp changed: %q", event.TimestampUTC)
	}
	for _, expected := range []string{
		"Product Name=Microsoft Defender Antivirus",
		"Threat Name=Trojan:Win32/VgtFixture",
		"Severity Name=Schwerwiegend",
		`Path=C:\Users\Test\evil.exe`,
		`Detection User=VGT-TESTHOST\operator`,
	} {
		if !strings.Contains(event.Message, expected) {
			t.Fatalf("message lost field %q: %q", expected, event.Message)
		}
	}
	if !strings.Contains(event.Message, "; ") {
		t.Fatalf("message is not a key=value list: %q", event.Message)
	}
	parsed, err := time.Parse(time.RFC3339Nano, event.TimestampUTC)
	if err != nil || !parsed.Equal(time.Date(2026, 10, 25, 10, 0, 0, 123456700, time.UTC)) {
		t.Fatalf("defender timestamp does not round trip: %v", err)
	}
}

func TestParseDefenderRecordRejectsInvalidRecords(t *testing.T) {
	cases := []struct {
		name   string
		record winapi.EventLogRecord
	}{
		{name: "empty-xml", record: winapi.EventLogRecord{RecordID: 1}},
		{name: "no-record-id", record: winapi.EventLogRecord{XML: []byte(defenderDetectionEventXML)}},
		{
			name: "unknown-event-id",
			record: defenderFixtureRecord(strings.Replace(defenderDetectionEventXML,
				"<EventID>1116</EventID>", "<EventID>4688</EventID>", 1)),
		},
		{
			name: "oversized-xml",
			record: winapi.EventLogRecord{
				RecordID: 1,
				XML:      []byte(strings.Repeat("x", defenderMaximumXMLBytes+1)),
			},
		},
		{name: "malformed-xml", record: winapi.EventLogRecord{RecordID: 1, XML: []byte("<Event><System>")}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if event, err := parseDefenderRecord(testCase.record); err == nil {
				t.Fatalf("accepted invalid Defender record: %+v", event)
			}
		})
	}
}

func TestDefenderMessageIsBounded(t *testing.T) {
	fields := make([]defenderDataField, 0, defenderMaximumMessageFields+10)
	for index := 0; index < defenderMaximumMessageFields+10; index++ {
		fields = append(fields, defenderDataField{
			Name:  "Field" + strings.Repeat("N", index%32),
			Value: strings.Repeat("v", 2048),
		})
	}
	fields[0] = defenderDataField{Name: "Threat Name", Value: strings.Repeat("w", 5000)}
	message := defenderEventMessage(fields)
	if len(message) > defenderMaximumMessageChars {
		t.Fatalf("message exceeded the hard bound: %d", len(message))
	}
	if len(message) == 0 {
		t.Fatal("bounded message is empty")
	}
	if strings.Count(message, "Threat Name=") != 1 {
		t.Fatalf("duplicate field handling failed: %q", message[:64])
	}
}

func TestDefenderMessageStripsControlCharactersAndDeduplicates(t *testing.T) {
	message := defenderEventMessage([]defenderDataField{
		{Name: "Path", Value: "evil\n&#9;name"},
		{Name: "path", Value: "duplicate"},
		{Name: "", Value: "anonymous"},
	})
	if strings.ContainsAny(message, "\n\r\t") {
		t.Fatalf("control characters reached the message: %q", message)
	}
	if strings.Count(strings.ToLower(message), "path=") != 1 {
		t.Fatalf("duplicate names were not collapsed: %q", message)
	}
	if !strings.Contains(message, "anonymous") {
		t.Fatalf("unnamed field was dropped: %q", message)
	}
}

func TestSanitizeDefenderTextBounds(t *testing.T) {
	if got := sanitizeDefenderText(strings.Repeat("a", 5000), defenderMaximumFieldValue); len(got) > defenderMaximumFieldValue {
		t.Fatalf("field value bound failed: %d", len(got))
	}
	if got := sanitizeDefenderText("  padded\n\tvalue  ", defenderMaximumFieldValue); got != "padded  value" {
		t.Fatalf("sanitization changed text unexpectedly: %q", got)
	}
	if got := sanitizeDefenderText(strings.Repeat("ä", 100), 50); len(got) > 50 || !strings.HasPrefix(got, "ä") {
		t.Fatalf("UTF-8 aware truncation failed: %q", got)
	}
	if got := sanitizeDefenderText("bad\x00\u0001text", defenderMaximumFieldValue); got != "badtext" {
		t.Fatalf("control characters were not stripped: %q", got)
	}
}

func TestDefenderWatcherStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan defenderEvent, 8)
	faults := make(chan error, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		(defenderWatcher{}).Run(ctx, events, faults)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("defender sensor did not stop on cancellation")
	}
	for len(faults) > 0 {
		fault := <-faults
		if isEventLogAccessDeniedError(fault) || isEventLogChannelUnavailableError(fault) {
			t.Skipf("Defender operational channel unavailable for this account: %v", fault)
		}
		t.Fatalf("clean cancellation reported a fault: %v", fault)
	}
}

func TestDefenderRecordHandlingAdvancesCursor(t *testing.T) {
	output, faults := make(chan defenderEvent, 2), make(chan error, 2)
	var cursor int64
	if err := handleDefenderRecord(context.Background(), defenderFixtureRecord(defenderDetectionEventXML), &cursor, output, faults); err != nil {
		t.Fatal(err)
	}
	if len(output) != 1 || len(faults) != 0 {
		t.Fatalf("unexpected delivery/fault count: %d/%d", len(output), len(faults))
	}
	if cursor != 4242 {
		t.Fatalf("delivered Defender record did not commit the cursor: %d", cursor)
	}
}

func TestDefenderMalformedRecordAdvancesCursorAndReportsFault(t *testing.T) {
	output, faults := make(chan defenderEvent, 2), make(chan error, 2)
	var cursor int64
	record := winapi.EventLogRecord{RecordID: 7, XML: []byte("<Event><System>"), TimeCreated: time.Now().UTC()}
	if err := handleDefenderRecord(context.Background(), record, &cursor, output, faults); err != nil {
		t.Fatalf("malformed record terminated the stream: %v", err)
	}
	if len(output) != 0 {
		t.Fatal("malformed Defender record was delivered")
	}
	if len(faults) != 1 {
		t.Fatalf("malformed Defender record was not reported: %d", len(faults))
	}
	if cursor != 7 {
		t.Fatalf("malformed record would be replayed after restart: cursor=%d", cursor)
	}
}

func TestDefenderCancelledDeliveryDoesNotAdvanceCursor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cursor int64
	err := handleDefenderRecord(ctx, defenderFixtureRecord(defenderDetectionEventXML), &cursor, make(chan defenderEvent), make(chan error, 1))
	if !errors.Is(err, context.Canceled) || cursor != 0 {
		t.Fatalf("cancelled Defender delivery committed the cursor: cursor=%d err=%v", cursor, err)
	}
}

func TestDefenderStreamUsesCursorForResumeQuery(t *testing.T) {
	cursor := int64(4242)
	var calls int
	var gotChannel, gotXPath string
	var gotStart int64
	stream := func(_ context.Context, channel, xpath string, startAfter int64) (<-chan winapi.EventLogRecord, <-chan error, error) {
		calls++
		gotChannel, gotXPath, gotStart = channel, xpath, startAfter
		return nil, nil, errors.New("fixture subscription rejected")
	}
	err := streamDefenderEvents(context.Background(), stream, &cursor, make(chan defenderEvent), make(chan error, 1))
	if err == nil {
		t.Fatal("fixture stream rejection was swallowed")
	}
	if calls != 1 || gotChannel != defenderOperationalChannel || gotStart != cursor {
		t.Fatalf("resume subscription = %q %q %d, calls=%d", gotChannel, gotXPath, gotStart, calls)
	}
	if !strings.Contains(gotXPath, "EventRecordID > 4242") {
		t.Fatalf("resume query lost the EventRecordID filter: %q", gotXPath)
	}
}

func TestDefenderStreamWithoutCursorRequestsFutureEvents(t *testing.T) {
	cursor := int64(0)
	var gotStart int64
	var gotXPath string
	stream := func(_ context.Context, _, xpath string, startAfter int64) (<-chan winapi.EventLogRecord, <-chan error, error) {
		gotStart, gotXPath = startAfter, xpath
		return nil, nil, errors.New("fixture subscription rejected")
	}
	_ = streamDefenderEvents(context.Background(), stream, &cursor, make(chan defenderEvent), make(chan error, 1))
	if gotStart != 0 {
		t.Fatalf("initial Defender subscription is not future-only: %d", gotStart)
	}
	if strings.Contains(gotXPath, "EventRecordID") {
		t.Fatalf("initial Defender query must not replay history: %q", gotXPath)
	}
}

func isEventLogAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "access is denied") || strings.Contains(message, "zugriff verweigert") || strings.Contains(message, "access denied")
}

func isEventLogChannelUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "channel") && (strings.Contains(message, "not found") || strings.Contains(message, "nicht gefunden"))
}
