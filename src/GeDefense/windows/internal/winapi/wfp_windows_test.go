// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"net/netip"
	"testing"
	"unsafe"
)

func TestWFPStructLayoutsMatchWindowsSDKx64(t *testing.T) {
	if got := unsafe.Sizeof(fwpmSession0{}); got != 72 {
		t.Fatalf("fwpmSession0 size=%d, want 72", got)
	}
	if got := unsafe.Sizeof(fwpmSublayer0{}); got != 72 {
		t.Fatalf("fwpmSublayer0 size=%d, want 72", got)
	}
	if got := unsafe.Sizeof(fwpmFilter0{}); got != 200 {
		t.Fatalf("fwpmFilter0 size=%d, want 200", got)
	}
	if got := unsafe.Offsetof(fwpmFilter0{}.Action); got != 128 {
		t.Fatalf("fwpmFilter0.Action offset=%d, want 128", got)
	}
	if got := unsafe.Offsetof(fwpmFilter0{}.FilterId); got != 176 {
		t.Fatalf("fwpmFilter0.FilterId offset=%d, want 176", got)
	}
	if got := unsafe.Sizeof(fwpmFilterCondition0{}); got != 40 {
		t.Fatalf("fwpmFilterCondition0 size=%d, want 40", got)
	}
	if got := unsafe.Sizeof(fwpConditionValue0{}); got != 16 {
		t.Fatalf("fwpConditionValue0 size=%d, want 16", got)
	}
	if got := unsafe.Sizeof(mibTCPRow{}); got != 20 {
		t.Fatalf("mibTCPRow size=%d, want 20", got)
	}
}

func TestWFPPlanDryRunAndTCPTargetValidation(t *testing.T) {
	engine := NewWFPEngine()
	defer func() { _ = engine.Close() }()

	status, err := engine.SyncPolicy(context.Background(), WFPConfig{
		DryRun:            true,
		BlockMetadata:     true,
		PinDNSToResolvers: true,
		AllowedDNSServers: []netip.Addr{netip.MustParseAddr("9.9.9.9")},
	})
	if err != nil {
		t.Fatalf("SyncPolicy DryRun: %v", err)
	}
	if !status.DryRun || status.Active || status.PlannedRules != 10 {
		t.Fatalf("unexpected DryRun status: %+v", status)
	}

	if _, err := BuildWFPPlan(WFPConfig{BlockAppPaths: []string{"relative.exe"}}); err == nil {
		t.Fatal("expected relative BlockAppPaths rejection")
	}
	if _, err := buildDeleteTCBRow(TCPKillTarget{LocalIP: netip.MustParseAddr("127.0.0.1"), LocalPort: 1234, RemoteIP: netip.MustParseAddr("::1"), RemotePort: 443}); err == nil {
		t.Fatal("expected IPv6 rejection in IPv4 SetTcpEntry helper")
	}
	row, err := buildDeleteTCBRow(TCPKillTarget{
		LocalIP:    netip.MustParseAddr("127.0.0.1"),
		LocalPort:  12345,
		RemoteIP:   netip.MustParseAddr("192.0.2.10"),
		RemotePort: 443,
	})
	if err != nil || row.State != mibTCPStateDeleteTCB {
		t.Fatalf("unexpected row: %+v err=%v", row, err)
	}
}

func TestWFPLiveEngineSmoke(t *testing.T) {
	engine := NewWFPEngine()
	defer func() { _ = engine.Close() }()

	status, err := engine.SyncPolicy(context.Background(), WFPConfig{
		DryRun:        false,
		BlockMetadata: true,
	})
	if err != nil {
		t.Skipf("live WFP NOT_TESTED (requires Administrator/BFE privilege): %v", err)
	}
	if !status.Active || len(status.FilterIDs) != 4 {
		t.Fatalf("expected 4 active metadata filters, got %+v", status)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
