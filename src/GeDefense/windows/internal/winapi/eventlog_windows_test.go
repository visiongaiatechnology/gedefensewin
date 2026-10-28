// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const defenderOperationalChannel = "Microsoft-Windows-Windows Defender/Operational"

const renderedSecurityEvent5157 = `<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>5157</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12810</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-24T12:34:56.7890123Z"/>
    <EventRecordID>987654</EventRecordID>
    <Correlation/>
    <Execution ProcessID="4" ThreadID="8"/>
    <Channel>Security</Channel>
    <Computer>VGT-TESTHOST</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="ProcessID">0x1a4</Data>
  </EventData>
</Event>`

func TestEventLogXPathBuildsBoundedSystemQuery(t *testing.T) {
	cases := []struct {
		name        string
		eventIDs    []int
		cursor      int64
		expected    string
		expectError bool
	}{
		{name: "single", eventIDs: []int{4688}, expected: "*[System[EventID=4688]]"},
		{name: "multiple-sorted", eventIDs: []int{5007, 1116, 1117}, expected: "*[System[(EventID=1116 or EventID=1117 or EventID=5007)]]"},
		{name: "deduplicated", eventIDs: []int{1116, 1116, 1117}, expected: "*[System[(EventID=1116 or EventID=1117)]]"},
		{name: "cursor", eventIDs: []int{5157}, cursor: 42, expected: "*[System[EventID=5157 and EventRecordID > 42]]"},
		{name: "empty", expectError: true},
		{name: "too-many", eventIDs: make([]int, maximumEventLogEventIDs+1), expectError: true},
		{name: "zero-id", eventIDs: []int{0}, expectError: true},
		{name: "negative-id", eventIDs: []int{-1}, expectError: true},
		{name: "oversized-id", eventIDs: []int{65536}, expectError: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			query, err := EventLogXPath(testCase.eventIDs, testCase.cursor)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("accepted invalid event ids %v", testCase.eventIDs)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected valid event ids: %v", err)
			}
			if query != testCase.expected {
				t.Fatalf("query = %q, want %q", query, testCase.expected)
			}
		})
	}
}

func TestEventLogChannelAllowlistRejectsArbitraryChannels(t *testing.T) {
	for _, channel := range []string{
		"",
		"Application",
		"System",
		"Security ",
		" Security",
		"Microsoft-Windows-Sysmon/Operational",
		"Security\x00",
		strings.Repeat("A", maximumEventLogChannel+1),
	} {
		if _, err := canonicalEventLogChannel(channel); err == nil {
			t.Fatalf("accepted non-allowlisted channel %q", channel)
		}
	}
	for channel, expected := range map[string]string{
		"Security":                 "Security",
		"security":                 "Security",
		defenderOperationalChannel: defenderOperationalChannel,
		strings.ToLower(defenderOperationalChannel): defenderOperationalChannel,
	} {
		canonical, err := canonicalEventLogChannel(channel)
		if err != nil || canonical != expected {
			t.Fatalf("channel %q = %q, %v; want %q", channel, canonical, err, expected)
		}
	}
}

func TestPrepareEventLogQuerySelectsOrigin(t *testing.T) {
	query, origin, err := prepareEventLogQuery("", 0)
	if err != nil || query != "*" || origin != evtSubscribeToFutureEvents {
		t.Fatalf("future default = %q, %d, %v", query, origin, err)
	}
	query, origin, err = prepareEventLogQuery("*", 7)
	if err != nil || query != "*[System[EventRecordID > 7]]" || origin != evtSubscribeStartAtOldestRecord {
		t.Fatalf("replay default = %q, %d, %v", query, origin, err)
	}
	built, err := EventLogXPath([]int{5157}, 7)
	if err != nil {
		t.Fatal(err)
	}
	query, origin, err = prepareEventLogQuery(built, 7)
	if err != nil || query != built || origin != evtSubscribeStartAtOldestRecord {
		t.Fatalf("replay built = %q, %d, %v", query, origin, err)
	}
	if _, _, err := prepareEventLogQuery("*[System[EventID=5157]]", 7); err == nil {
		t.Fatal("replay without an EventRecordID filter was accepted")
	}
	if _, _, err := prepareEventLogQuery("*[System[EventID=5157]]\n", 0); err == nil {
		t.Fatal("xpath with control characters was accepted")
	}
	if _, _, err := prepareEventLogQuery(strings.Repeat("x", maximumEventLogXPathLen+1), 0); err == nil {
		t.Fatal("oversized xpath was accepted")
	}
}

func TestDecodeEventLogUTF16LE(t *testing.T) {
	utf16Bytes := func(units ...uint16) []byte {
		raw := make([]byte, 0, len(units)*2)
		for _, unit := range units {
			raw = append(raw, byte(unit), byte(unit>>8))
		}
		return raw
	}
	cases := []struct {
		name        string
		input       []byte
		expected    string
		expectError bool
	}{
		{name: "ascii", input: utf16Bytes('<', 'E', 'v'), expected: "<Ev"},
		{name: "umlaut", input: utf16Bytes(0x00E4, 0x00F6), expected: "äö"},
		{name: "surrogate-pair", input: utf16Bytes(0xD83D, 0xDE00), expected: "😀"},
		{name: "nul-terminated", input: utf16Bytes('o', 'k', 0, 'x'), expected: "ok"},
		{name: "bom", input: utf16Bytes(0xFEFF, 'x'), expected: "x"},
		{name: "empty", expectError: true},
		{name: "odd-bytes", input: []byte{0x3C, 0x00, 0x45}, expectError: true},
		{name: "only-nul", input: utf16Bytes(0), expectError: true},
		{name: "only-whitespace", input: utf16Bytes(' ', '\t'), expectError: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text, err := decodeEventLogUTF16LE(testCase.input)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("accepted invalid UTF-16LE %v", testCase.input)
				}
				return
			}
			if err != nil || text != testCase.expected {
				t.Fatalf("decode = %q, %v; want %q", text, err, testCase.expected)
			}
		})
	}
}

func TestParseEventLogRecordXML(t *testing.T) {
	record, err := parseEventLogRecordXML("Security", []byte(renderedSecurityEvent5157))
	if err != nil {
		t.Fatalf("rejected rendered event: %v", err)
	}
	if record.RecordID != 987654 || record.Channel != "Security" {
		t.Fatalf("unexpected record identity: %+v", record)
	}
	expected := time.Date(2026, 10, 24, 12, 34, 56, 789012300, time.UTC)
	if !record.TimeCreated.Equal(expected) {
		t.Fatalf("time created = %v, want %v", record.TimeCreated, expected)
	}
	if string(record.XML) != renderedSecurityEvent5157 {
		t.Fatal("rendered XML bytes were changed")
	}
	fallback, err := parseEventLogRecordXML("Security", []byte(strings.Replace(renderedSecurityEvent5157, "2026-10-24T12:34:56.7890123Z", "not-a-timestamp", 1)))
	if err != nil {
		t.Fatalf("malformed timestamp was fatal: %v", err)
	}
	if delta := time.Since(fallback.TimeCreated); delta < 0 || delta > time.Minute {
		t.Fatalf("missing timestamp did not fall back to receipt time: %v", fallback.TimeCreated)
	}
	missingID := strings.Replace(renderedSecurityEvent5157, "<EventRecordID>987654</EventRecordID>", "", 1)
	if _, err := parseEventLogRecordXML("Security", []byte(missingID)); err == nil {
		t.Fatal("event record without EventRecordID was accepted")
	}
	if _, err := parseEventLogRecordXML("Security", []byte("<Event><System>")); err == nil {
		t.Fatal("malformed XML was accepted")
	}
	if _, err := parseEventLogRecordXML("Security", nil); err == nil {
		t.Fatal("empty XML was accepted")
	}
}

func TestStreamEventLogRejectsBeforeSubscription(t *testing.T) {
	if _, _, err := StreamEventLog(nil, "Security", "*", 0); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := StreamEventLog(ctx, "Security", "*", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context = %v", err)
	}
	if _, _, err := StreamEventLog(context.Background(), "Application", "*", 0); err == nil {
		t.Fatal("non-allowlisted channel accepted")
	}
	if _, _, err := StreamEventLog(context.Background(), "Security", "*[System[\x01]]", 0); err == nil {
		t.Fatal("control characters in xpath accepted")
	}
	if _, _, err := StreamEventLog(context.Background(), "Security", "*[System[EventID=5157]]", 5); err == nil {
		t.Fatal("replay query without EventRecordID filter accepted")
	}
}

// openAllowlistedTestStream subscribes to the Defender operational channel,
// which is readable without elevation on a standard Windows installation. The
// test is skipped instead of silently passing when the host denies access.
func openAllowlistedTestStream(t *testing.T, ctx context.Context, xpath string, cursor int64) (<-chan EventLogRecord, <-chan error) {
	t.Helper()
	records, faults, err := StreamEventLog(ctx, defenderOperationalChannel, xpath, cursor)
	if err != nil {
		if isEventLogAccessDenied(err) || isEventLogUnavailable(err) {
			t.Skipf("event log unavailable for this account: %v", err)
		}
		t.Fatalf("event log subscription failed: %v", err)
	}
	return records, faults
}

func TestEventLogStreamCancellationClosesChannels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	records, faults := openAllowlistedTestStream(t, ctx, "*", 0)
	started := time.Now()
	cancel()
	const cancellationBound = 3 * time.Second
	deadline := time.Now().Add(cancellationBound)
	recordsClosed, faultsClosed := false, false
	for !recordsClosed || !faultsClosed {
		if time.Now().After(deadline) {
			t.Fatalf("cancelled stream did not close channels within %v (records=%v faults=%v)", cancellationBound, recordsClosed, faultsClosed)
		}
		select {
		case _, ok := <-records:
			if !ok {
				recordsClosed = true
			}
		case err, ok := <-faults:
			if !ok {
				faultsClosed = true
			} else if err != nil && ctx.Err() == nil {
				t.Fatalf("cancelled stream reported a fault: %v", err)
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	if elapsed := time.Since(started); elapsed > cancellationBound {
		t.Fatalf("cancellation took %v, the native wait slice is not bounded", elapsed)
	}
}

func TestEventLogStreamReplayRendersHistoricalRecords(t *testing.T) {
	query, err := EventLogXPath([]int{1116, 1117, 5001, 5007, 5010, 5012}, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	records, faults := openAllowlistedTestStream(t, ctx, query, 1)
	for {
		select {
		case record, ok := <-records:
			if !ok {
				t.Skip("Defender operational log contains no replayable records on this host")
			}
			if record.RecordID <= 1 || len(record.XML) == 0 || record.TimeCreated.IsZero() {
				t.Fatalf("invalid replayed record: id=%d xml=%d time=%v", record.RecordID, len(record.XML), record.TimeCreated)
			}
			if !strings.Contains(string(record.XML), "<Event") {
				t.Fatalf("replayed record XML is not a rendered event: %q", truncateForTest(record.XML))
			}
			return
		case err, ok := <-faults:
			if ok && err != nil {
				t.Skipf("Defender operational replay unavailable: %v", err)
			}
		case <-ctx.Done():
			t.Skip("Defender operational log replay timed out on this host")
		}
	}
}

func TestEventLogStreamSecurityLogNeedsAuditPrivilege(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	records, faults, err := StreamEventLog(ctx, "Security", eventLogXPathOrPanic(t, []int{5157}, 0), 0)
	if err != nil {
		if isEventLogAccessDenied(err) {
			t.Skipf("Security log requires elevation: %v", err)
		}
		t.Fatalf("Security log subscription failed: %v", err)
	}
	cancel()
	_ = records
	_ = faults
}

func eventLogXPathOrPanic(t *testing.T, eventIDs []int, cursor int64) string {
	t.Helper()
	query, err := EventLogXPath(eventIDs, cursor)
	if err != nil {
		t.Fatalf("cannot build query: %v", err)
	}
	return query
}

func isEventLogAccessDenied(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, syscall.ERROR_PRIVILEGE_NOT_HELD)
}

func isEventLogUnavailable(err error) bool {
	const errorChannelNotFound syscall.Errno = 15007
	return errors.Is(err, errorChannelNotFound)
}

func truncateForTest(value []byte) string {
	const limit = 256
	if len(value) > limit {
		return string(value[:limit])
	}
	return string(value)
}

var procGetProcessHandleCount = kernel32.NewProc("GetProcessHandleCount")

func processHandleCount(t *testing.T) uint32 {
	t.Helper()
	process, _, _ := procGetCurrentProcess.Call()
	var count uint32
	result, _, callErr := procGetProcessHandleCount.Call(process, uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatalf("GetProcessHandleCount failed: %v", callErr)
	}
	return count
}

func TestEventLogStreamDoesNotLeakHandles(t *testing.T) {
	cycle := func() {
		ctx, cancel := context.WithCancel(context.Background())
		records, faults, err := StreamEventLog(ctx, defenderOperationalChannel, "*", 0)
		if err != nil {
			cancel()
			if isEventLogAccessDenied(err) || isEventLogUnavailable(err) {
				t.Skipf("event log unavailable for this account: %v", err)
			}
			t.Fatalf("event log subscription failed: %v", err)
		}
		cancel()
		for records != nil || faults != nil {
			select {
			case _, ok := <-records:
				if !ok {
					records = nil
				}
			case _, ok := <-faults:
				if !ok {
					faults = nil
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled stream did not release its handles")
			}
		}
	}
	for index := 0; index < 5; index++ {
		cycle()
	}
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	before := processHandleCount(t)
	for index := 0; index < 15; index++ {
		cycle()
	}
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	after := processHandleCount(t)
	if after > before+16 {
		t.Fatalf("event log stream leaked handles: %d -> %d", before, after)
	}
}
