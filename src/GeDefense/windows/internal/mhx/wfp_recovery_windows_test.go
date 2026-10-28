// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"encoding/xml"
	"errors"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func wfpFixtureFields(overrides map[string]string) map[string]string {
	fields := map[string]string{
		"ProcessID":     "0x1a4",
		"Application":   `\device\harddiskvolume3\windows\system32\chrome.exe`,
		"Direction":     "%%14593",
		"SourceAddress": "10.1.2.3",
		"SourcePort":    "50123",
		"DestAddress":   "8.8.8.8",
		"DestPort":      "443",
		"Protocol":      "6",
		"FilterRTID":    "0",
		"FilterOrigin":  "VGT-GeDefense-TI-core",
	}
	for name, value := range overrides {
		if value == "" {
			delete(fields, name)
			continue
		}
		fields[name] = value
	}
	return fields
}

func wfpBlockRecordXML(fields map[string]string) []byte {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var data strings.Builder
	for _, name := range names {
		data.WriteString(`<Data Name="`)
		_ = xml.EscapeText(&data, []byte(name))
		data.WriteString(`">`)
		_ = xml.EscapeText(&data, []byte(fields[name]))
		data.WriteString(`</Data>`)
	}
	return []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>5157</EventID></System><EventData>` + data.String() + `</EventData></Event>`)
}

func wfpRecordFixture(recordID int64, created time.Time, fields map[string]string) winapi.EventLogRecord {
	return winapi.EventLogRecord{
		RecordID:    recordID,
		Channel:     wfpSecurityChannel,
		XML:         wfpBlockRecordXML(fields),
		TimeCreated: created,
	}
}

func TestWFPHistoricalEventKeepsReceiptHealthAndOriginalEventTime(t *testing.T) {
	ctx := context.Background()
	output, health := make(chan wfpBlockEvent, 1), make(chan time.Time, 2)
	var cursor int64
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	record := wfpRecordFixture(42, created, wfpFixtureFields(nil))
	received := time.Now().UTC()
	if err := normalizeWFPRecord(ctx, record, &cursor, output, health, received); err != nil {
		t.Fatal(err)
	}
	if got := <-health; !got.Equal(received) {
		t.Fatalf("sensor health used historical event time: %v", got)
	}
	event := <-output
	if !event.TimestampUTC.Equal(created) || event.TimestampUTC.Year() != 2020 {
		t.Fatalf("event time changed: %+v", event)
	}
	if event.PID != 420 || event.RemoteIP != "8.8.8.8" || event.RemotePort != 443 || event.LocalPort != 50123 || event.Protocol != 6 || event.RecordID != 42 {
		t.Fatalf("event validation changed: %+v", event)
	}
	if cursor != 42 {
		t.Fatalf("delivered record cursor was not committed: %d", cursor)
	}
	if err := normalizeWFPRecord(ctx, record, &cursor, output, health, received); err != nil || len(output) != 0 {
		t.Fatalf("resume duplicated an already delivered block: %v", err)
	}
	if cursor != 42 {
		t.Fatalf("duplicate record changed the cursor: %d", cursor)
	}
}

func TestWFPInboundDirectionUsesRemoteSource(t *testing.T) {
	fields := wfpFixtureFields(map[string]string{
		"Direction":     "%%14592",
		"SourceAddress": "1.1.1.1",
		"SourcePort":    "53",
		"DestAddress":   "10.1.2.3",
		"DestPort":      "60001",
	})
	var cursor int64
	output := make(chan wfpBlockEvent, 1)
	if err := normalizeWFPRecord(context.Background(), wfpRecordFixture(7, time.Now().UTC(), fields), &cursor, output, make(chan time.Time, 2), time.Now()); err != nil {
		t.Fatal(err)
	}
	event := <-output
	if event.Direction != "Inbound" || event.RemoteIP != "1.1.1.1" || event.RemotePort != 53 || event.LocalPort != 60001 {
		t.Fatalf("inbound mapping changed: %+v", event)
	}
}

func TestWFPHexIdentifiersAreAccepted(t *testing.T) {
	fields := wfpFixtureFields(map[string]string{
		"ProcessID":  "0x1A4",
		"Protocol":   "0x6",
		"FilterRTID": "0x3039",
		"DestPort":   "0x1BB",
	})
	var cursor int64
	output := make(chan wfpBlockEvent, 1)
	if err := normalizeWFPRecord(context.Background(), wfpRecordFixture(9, time.Now().UTC(), fields), &cursor, output, make(chan time.Time, 2), time.Now()); err != nil {
		t.Fatal(err)
	}
	event := <-output
	if event.PID != 420 || event.Protocol != 6 || event.FilterRuntimeID != 12345 || event.RemotePort != 443 {
		t.Fatalf("hex identifiers were not parsed: %+v", event)
	}
}

// A structurally valid record with an unusable remote address is policy
// filtered: it refreshes receipt-time health and commits the cursor (matching
// the previous bridge) but is never delivered to the correlation pipeline.
func TestWFPFilteredRemoteAddressAdvancesCursorWithReceiptHealth(t *testing.T) {
	cases := []string{"127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "not-an-ip", ""}
	for _, address := range cases {
		t.Run(address, func(t *testing.T) {
			var cursor int64
			output, health := make(chan wfpBlockEvent, 1), make(chan time.Time, 2)
			fields := wfpFixtureFields(map[string]string{"DestAddress": address})
			err := normalizeWFPRecord(context.Background(), wfpRecordFixture(11, time.Now().UTC(), fields), &cursor, output, health, time.Now().UTC())
			if err != nil {
				t.Fatalf("valid record with unusable address was treated as malformed: %v", err)
			}
			if len(output) != 0 {
				t.Fatal("policy-filtered address was delivered")
			}
			if cursor != 11 {
				t.Fatalf("policy-filtered record did not commit the cursor: %d", cursor)
			}
			if len(health) != 1 {
				t.Fatalf("policy-filtered record did not refresh receipt-time health: %d", len(health))
			}
		})
	}
}

func TestWFPInvalidRecordCannotRefreshHealth(t *testing.T) {
	cases := []struct {
		name   string
		record winapi.EventLogRecord
	}{
		{name: "empty-xml", record: winapi.EventLogRecord{RecordID: 1}},
		{name: "zero-record-id", record: wfpRecordFixture(0, time.Now().UTC(), wfpFixtureFields(nil))},
		{name: "missing-event-time", record: wfpRecordFixture(1, time.Time{}, wfpFixtureFields(nil))},
		{name: "malformed-xml", record: winapi.EventLogRecord{RecordID: 1, XML: []byte("<Event><System>"), TimeCreated: time.Now().UTC()}},
		{name: "wrong-event-id", record: winapi.EventLogRecord{RecordID: 1, TimeCreated: time.Now().UTC(), XML: []byte(strings.Replace(string(wfpBlockRecordXML(wfpFixtureFields(nil))), "<EventID>5157</EventID>", "<EventID>4688</EventID>", 1))}},
		{name: "missing-pid", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"ProcessID": ""}))},
		{name: "invalid-pid", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"ProcessID": "0xZZ"}))},
		{name: "zero-pid", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"ProcessID": "0"}))},
		{name: "missing-protocol", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"Protocol": ""}))},
		{name: "zero-protocol", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"Protocol": "0"}))},
		{name: "unknown-direction", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"Direction": "%%1"}))},
		{name: "oversized-filter-origin", record: wfpRecordFixture(1, time.Now().UTC(), wfpFixtureFields(map[string]string{"FilterOrigin": strings.Repeat("o", wfpMaximumFilterOriginChars+1)}))},
		{
			name:   "oversized-xml",
			record: winapi.EventLogRecord{RecordID: 1, XML: []byte(strings.Repeat("x", wfpMaximumXMLBytes+1)), TimeCreated: time.Now().UTC()},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var cursor int64
			output, health := make(chan wfpBlockEvent, 1), make(chan time.Time, 1)
			err := normalizeWFPRecord(context.Background(), testCase.record, &cursor, output, health, time.Now().UTC())
			if err == nil {
				t.Fatalf("accepted invalid WFP record: %+v", testCase.record.RecordID)
			}
			if len(health) != 0 {
				t.Fatal("invalid WFP record refreshed health")
			}
			if len(output) != 0 || cursor != 0 {
				t.Fatalf("invalid record advanced output/cursor: cursor=%d", cursor)
			}
		})
	}
}

func TestWFPFieldBoundaryIsEnforced(t *testing.T) {
	var data strings.Builder
	for index := 0; index < wfpMaximumFields+1; index++ {
		data.WriteString(`<Data Name="Field`)
		data.WriteString(strings.Repeat("x", 4))
		data.WriteString(`">`)
		data.WriteString(strings.Repeat("v", 64))
		data.WriteString(`</Data>`)
	}
	record := winapi.EventLogRecord{
		RecordID:    1,
		XML:         []byte(`<Event><System><EventID>5157</EventID></System><EventData>` + data.String() + `</EventData></Event>`),
		TimeCreated: time.Now().UTC(),
	}
	var cursor int64
	if err := normalizeWFPRecord(context.Background(), record, &cursor, make(chan wfpBlockEvent, 1), make(chan time.Time, 1), time.Now().UTC()); err == nil {
		t.Fatal("field count boundary was not enforced")
	}
}

func TestWFPGeDefenseOriginDetection(t *testing.T) {
	cases := []struct {
		origin   string
		expected bool
	}{
		{origin: "VGT-GeDefense-TI-core", expected: true},
		{origin: "  VGT-GeDefense-TI-wfp  ", expected: true},
		{origin: "VGT-Other-TI-core", expected: false},
		{origin: "Windows Filtering Platform", expected: false},
		{origin: "", expected: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.origin, func(t *testing.T) {
			var cursor int64
			output := make(chan wfpBlockEvent, 1)
			fields := wfpFixtureFields(map[string]string{"FilterOrigin": testCase.origin})
			if err := normalizeWFPRecord(context.Background(), wfpRecordFixture(3, time.Now().UTC(), fields), &cursor, output, make(chan time.Time, 2), time.Now()); err != nil {
				t.Fatal(err)
			}
			event := <-output
			if event.GeDefenseOrigin != testCase.expected {
				t.Fatalf("GeDefenseOrigin = %v for %q", event.GeDefenseOrigin, testCase.origin)
			}
		})
	}
}

func TestWFPApplicationIsBounded(t *testing.T) {
	var cursor int64
	output := make(chan wfpBlockEvent, 1)
	fields := wfpFixtureFields(map[string]string{"Application": strings.Repeat("a", 3000)})
	if err := normalizeWFPRecord(context.Background(), wfpRecordFixture(5, time.Now().UTC(), fields), &cursor, output, make(chan time.Time, 2), time.Now()); err != nil {
		t.Fatal(err)
	}
	if event := <-output; len(event.Application) > wfpMaximumApplicationChars {
		t.Fatalf("application field exceeded its bound: %d", len(event.Application))
	}
}

func TestWFPCancelledDeliveryDoesNotAdvanceCursor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cursor int64
	health := make(chan time.Time, 1)
	record := wfpRecordFixture(9, time.Now().UTC(), wfpFixtureFields(nil))
	err := normalizeWFPRecord(ctx, record, &cursor, make(chan wfpBlockEvent), health, time.Now())
	if !errors.Is(err, context.Canceled) || cursor != 0 || len(health) != 0 {
		t.Fatalf("cancelled delivery committed cursor or health: cursor=%d err=%v", cursor, err)
	}
}

func TestWFPWatcherStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan wfpBlockEvent, 8)
	health := make(chan time.Time, 8)
	faults := make(chan error, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		(wfpBlockWatcher{}).Run(ctx, events, health, faults)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WFP sensor did not stop on cancellation")
	}
	for len(faults) > 0 {
		fault := <-faults
		if isEventLogAccessDeniedError(fault) || isEventLogChannelUnavailableError(fault) {
			t.Skipf("Security event log unavailable for this account: %v", fault)
		}
		t.Fatalf("clean cancellation reported a fault: %v", fault)
	}
}

func FuzzWFPRecordXML(f *testing.F) {
	f.Add(wfpBlockRecordXML(wfpFixtureFields(nil)), int64(7))
	f.Add(wfpBlockRecordXML(wfpFixtureFields(map[string]string{"DestAddress": "::1"})), int64(0))
	f.Add([]byte(`<Event><System><EventID>5157</EventID></System></Event>`), int64(1))
	f.Add([]byte(""), int64(0))
	f.Fuzz(func(t *testing.T, raw []byte, recordID int64) {
		if len(raw) > wfpMaximumXMLBytes || recordID < 0 || recordID > math.MaxInt32 {
			return
		}
		record := winapi.EventLogRecord{
			RecordID:    recordID,
			Channel:     wfpSecurityChannel,
			XML:         raw,
			TimeCreated: time.Now().UTC(),
		}
		var cursor int64
		output, health := make(chan wfpBlockEvent, 1), make(chan time.Time, 1)
		err := normalizeWFPRecord(context.Background(), record, &cursor, output, health, time.Now().UTC())
		if err != nil && len(health) != 0 {
			t.Fatal("rejected WFP record refreshed health")
		}
		if len(output) > 1 {
			t.Fatal("WFP output is not bounded")
		}
		if cursor != 0 && cursor != recordID {
			t.Fatalf("cursor committed a different record: %d", cursor)
		}
	})
}
