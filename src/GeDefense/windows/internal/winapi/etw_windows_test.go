// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"fmt"
	"testing"
	"time"
	"unsafe"
)

func TestETWStructLayoutsMatchWindowsSDKx64(t *testing.T) {
	if got := unsafe.Sizeof(wnodeHeader{}); got != 48 {
		t.Fatalf("wnodeHeader size=%d, want 48", got)
	}
	if got := unsafe.Sizeof(eventTraceProperties{}); got != 120 {
		t.Fatalf("eventTraceProperties size=%d, want 120", got)
	}
	if got := unsafe.Offsetof(eventTraceProperties{}.LoggerNameOffset); got != 116 {
		t.Fatalf("LoggerNameOffset=%d, want 116", got)
	}
	if got := unsafe.Sizeof(eventTraceLogfileW{}); got != 448 {
		t.Fatalf("eventTraceLogfileW size=%d, want 448", got)
	}
	if got := unsafe.Offsetof(eventTraceLogfileW{}.EventRecordCallback); got != 424 {
		t.Fatalf("EventRecordCallback offset=%d, want 424", got)
	}
	if got := unsafe.Offsetof(eventTraceLogfileW{}.Context); got != 440 {
		t.Fatalf("Context offset=%d, want 440", got)
	}
	if got := unsafe.Sizeof(eventHeader{}); got != 80 {
		t.Fatalf("eventHeader size=%d, want 80", got)
	}
	if got := unsafe.Sizeof(eventRecord{}); got != 112 {
		t.Fatalf("eventRecord size=%d, want 112", got)
	}
	if got := unsafe.Offsetof(eventRecord{}.UserData); got != 96 {
		t.Fatalf("UserData offset=%d, want 96", got)
	}
	if got := unsafe.Sizeof(traceEventInfoHeader{}); got != 112 {
		t.Fatalf("traceEventInfoHeader size=%d, want 112", got)
	}
	if got := unsafe.Sizeof(eventPropertyInfo{}); got != 24 {
		t.Fatalf("eventPropertyInfo size=%d, want 24", got)
	}
	if got := unsafe.Sizeof(propertyDataDescriptor{}); got != 16 {
		t.Fatalf("propertyDataDescriptor size=%d, want 16", got)
	}
}

func TestETWSyntheticRecordParsing(t *testing.T) {
	if _, err := parseSyntheticEventRecord([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected truncated synthetic record to fail")
	}

	var rec eventRecord
	rec.EventHeader.ProviderId = GUIDKernelProcess
	rec.EventHeader.EventDescriptor.Id = 1
	rec.EventHeader.ProcessId = 4242
	rec.EventHeader.ThreadId = 88
	rec.EventHeader.TimeStamp = filetimeUnixDelta + 10_000_000

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&rec)), unsafe.Sizeof(rec))
	ev, err := parseSyntheticEventRecord(raw)
	if err != nil {
		t.Fatalf("parseSyntheticEventRecord: %v", err)
	}
	if ev.ProviderName != "Kernel-Process" || ev.Kind != "ProcessStart" {
		t.Fatalf("unexpected classification: %+v", ev)
	}
	if ev.PID != 4242 || ev.TID != 88 || ev.TimestampUTC.Unix() != 1 {
		t.Fatalf("unexpected parsed fields: %+v", ev)
	}
}

func TestETWSessionValidationAndLiveSmoke(t *testing.T) {
	if _, err := NewETWSession(ETWConfig{}); err == nil {
		t.Fatal("expected empty config rejection")
	}

	session, err := NewETWSession(ETWConfig{
		SessionName: fmt.Sprintf("VGT-GeDefense-ETWTest-%d", time.Now().UnixNano()),
		Providers:   []ETWProviderConfig{{GUID: GUIDKernelProcess}},
		QueueSize:   128,
	})
	if err != nil {
		t.Fatalf("NewETWSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	if err := session.Start(ctx); err != nil {
		t.Skipf("live ETW NOT_TESTED (requires SeSystemProfilePrivilege/admin): %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if st := session.Status(); st.Running {
		t.Fatalf("expected stopped status after Close: %+v", st)
	}
}
