// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type processIdentity struct {
	pid      uint32
	creation int64
}

type fakeProcessController struct {
	mu           sync.Mutex
	processes    []ProcessInfo
	listErr      error
	suspendErr   error
	resumeErr    func(pid uint32, creationUnixNano int64) error
	suspendCalls []processIdentity
	resumeCalls  []processIdentity
}

func (f *fakeProcessController) ListProcesses(context.Context) ([]ProcessInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]ProcessInfo(nil), f.processes...), nil
}

func (f *fakeProcessController) Suspend(pid uint32, creationUnixNano int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.suspendCalls = append(f.suspendCalls, processIdentity{pid: pid, creation: creationUnixNano})
	return f.suspendErr
}

func (f *fakeProcessController) Resume(pid uint32, creationUnixNano int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumeCalls = append(f.resumeCalls, processIdentity{pid: pid, creation: creationUnixNano})
	if f.resumeErr != nil {
		return f.resumeErr(pid, creationUnixNano)
	}
	return nil
}

func (f *fakeProcessController) calls() (suspends, resumes []processIdentity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]processIdentity(nil), f.suspendCalls...), append([]processIdentity(nil), f.resumeCalls...)
}

func TestBrokerFreezeFiltersNamesAndProtections(t *testing.T) {
	clock := newFakeClock()
	controller := &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 41},
		{PID: 9002, Name: "MSTSC.EXE", CreationUnixNano: 42},
		{PID: 9003, Name: "bash.exe", CreationUnixNano: 43},
		{PID: 1, Name: "ssh-agent.exe", CreationUnixNano: 44},
		{PID: 500, Name: "lsass.exe", CreationUnixNano: 45},
		{PID: uint32(os.Getpid()), Name: "ssh-agent.exe", CreationUnixNano: 46},
	}}
	freezer := NewBrokerFreezer()
	report, err := freezer.Freeze(context.Background(), controller, clock.Now())
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if report.Frozen != 2 || report.Protected != 2 || report.Failed != 0 {
		t.Fatalf("unexpected freeze accounting: %+v", report)
	}
	if report.Status != BrokerStatusFrozenNotLocked {
		t.Fatalf("the honest broker status is missing: %q", report.Status)
	}
	// The critical-name boundary is defense in depth: lsass.exe never matches the
	// broker list and is never signalled.
	if !isProtectedProcessName("lsass.exe") {
		t.Fatal("lsass.exe is not in the critical-name boundary")
	}
	suspends, _ := controller.calls()
	if len(suspends) != 2 {
		t.Fatalf("unexpected suspend count: %d", len(suspends))
	}
	for _, suspend := range suspends {
		if suspend.pid == 1 || suspend.pid == 500 || suspend.pid == uint32(os.Getpid()) {
			t.Fatalf("a protected process was signalled: %+v", suspend)
		}
	}
	for index, want := range []processIdentity{{pid: 9001, creation: 41}, {pid: 9002, creation: 42}} {
		if suspends[index] != want {
			t.Fatalf("suspend %d: got %+v want %+v", index, suspends[index], want)
		}
	}
}

func TestBrokerFreezeIsIdempotentAndResumeUsesRecordedIdentity(t *testing.T) {
	clock := newFakeClock()
	controller := &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 41},
		{PID: 9002, Name: "gpg-agent.exe", CreationUnixNano: 42},
	}}
	freezer := NewBrokerFreezer()
	first, err := freezer.Freeze(context.Background(), controller, clock.Now())
	if err != nil || first.Frozen != 2 {
		t.Fatalf("first freeze: report=%+v err=%v", first, err)
	}
	second, err := freezer.Freeze(context.Background(), controller, clock.Now())
	if err != nil || second.Frozen != 0 {
		t.Fatalf("a second freeze was not idempotent: report=%+v err=%v", second, err)
	}
	suspends, _ := controller.calls()
	if len(suspends) != 2 {
		t.Fatalf("the idempotent freeze signalled again: %d", len(suspends))
	}
	resumed, err := freezer.Resume(context.Background(), controller, clock.Now())
	if err != nil || resumed.Resumed != 2 {
		t.Fatalf("resume: report=%+v err=%v", resumed, err)
	}
	_, resumes := controller.calls()
	if len(resumes) != 2 {
		t.Fatalf("unexpected resume count: %d", len(resumes))
	}
	for index, want := range []processIdentity{{pid: 9001, creation: 41}, {pid: 9002, creation: 42}} {
		if resumes[index] != want {
			t.Fatalf("resume %d: got %+v want %+v", index, resumes[index], want)
		}
	}
	if freezer.FrozenCount() != 0 {
		t.Fatalf("the frozen records survived a successful resume: %d", freezer.FrozenCount())
	}
}

func TestBrokerResumeRefusesRecycledPIDAndKeepsRecord(t *testing.T) {
	clock := newFakeClock()
	controller := &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 41},
	}}
	freezer := NewBrokerFreezer()
	if _, err := freezer.Freeze(context.Background(), controller, clock.Now()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	// The PID was recycled: the recorded creation time no longer matches.
	controller.resumeErr = func(pid uint32, creation int64) error {
		return ErrProcessIdentityMismatch
	}
	report, err := freezer.Resume(context.Background(), controller, clock.Now())
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if report.Failed != 1 || report.Resumed != 0 || report.Status != "resume-failed" {
		t.Fatalf("a recycled PID was not refused: %+v", report)
	}
	if freezer.FrozenCount() != 1 {
		t.Fatal("the failed identity must stay recorded for a retried clear")
	}
	// Once the identity is valid again the retried resume releases it.
	controller.resumeErr = nil
	retried, err := freezer.Resume(context.Background(), controller, clock.Now())
	if err != nil || retried.Resumed != 1 {
		t.Fatalf("the retried resume failed: report=%+v err=%v", retried, err)
	}
	if freezer.FrozenCount() != 0 {
		t.Fatal("the retried resume did not release the identity")
	}
}

func TestBrokerTTLBoundsTheResumeWindow(t *testing.T) {
	clock := newFakeClock()
	controller := &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 41},
	}}
	freezer := NewBrokerFreezer()
	if _, err := freezer.Freeze(context.Background(), controller, clock.Now()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	// Exactly at the TTL the record is still resumed.
	atBoundary := clock.Now().Add(BrokerFreezeTTL)
	if report, err := freezer.Resume(context.Background(), controller, atBoundary); err != nil || report.Resumed != 1 {
		t.Fatalf("the record at the TTL boundary was not resumed: report=%+v err=%v", report, err)
	}
	// Past the TTL it is dropped without a signal.
	clock = newFakeClock()
	controller = &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 41},
	}}
	freezer = NewBrokerFreezer()
	if _, err := freezer.Freeze(context.Background(), controller, clock.Now()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	expiredAt := clock.Now().Add(BrokerFreezeTTL + time.Second)
	report, err := freezer.Resume(context.Background(), controller, expiredAt)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if report.Expired != 1 || report.Resumed != 0 || report.Status != "identity-ttl-expired" {
		t.Fatalf("an expired identity was not reported: %+v", report)
	}
	if _, resumes := controller.calls(); len(resumes) != 0 {
		t.Fatal("an expired identity was signalled")
	}
	if freezer.FrozenCount() != 0 {
		t.Fatal("an expired identity stayed recorded")
	}
}

func TestBrokerFreezeIsBounded(t *testing.T) {
	clock := newFakeClock()
	processes := make([]ProcessInfo, 0, BrokerMaxScan+50)
	for index := 0; index < BrokerMaxScan+50; index++ {
		processes = append(processes, ProcessInfo{
			PID: uint32(1000 + index), Name: "ssh-agent.exe", CreationUnixNano: int64(index + 1),
		})
	}
	controller := &fakeProcessController{processes: processes}
	freezer := NewBrokerFreezer()
	report, err := freezer.Freeze(context.Background(), controller, clock.Now())
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if !report.Bounded {
		t.Fatal("the bounded scan was not reported")
	}
	if report.Frozen != BrokerMaxFrozen {
		t.Fatalf("unexpected frozen count: %d", report.Frozen)
	}
	suspends, _ := controller.calls()
	if len(suspends) != BrokerMaxFrozen {
		t.Fatalf("the freezer signalled beyond its bound: %d", len(suspends))
	}
	if report.Scanned > BrokerMaxScan {
		t.Fatalf("the scan exceeded its bound: %d", report.Scanned)
	}
}

func TestBrokerFreezeSkipsMissingIdentity(t *testing.T) {
	clock := newFakeClock()
	controller := &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 0},
	}}
	freezer := NewBrokerFreezer()
	report, err := freezer.Freeze(context.Background(), controller, clock.Now())
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if report.Failed != 1 || report.Frozen != 0 {
		t.Fatalf("a process without an identity was frozen: %+v", report)
	}
	if suspends, _ := controller.calls(); len(suspends) != 0 {
		t.Fatal("a process without an identity was signalled")
	}
}

func TestBrokersPhaseReportsFrozenNotLocked(t *testing.T) {
	clock := newFakeClock()
	controller := &fakeProcessController{processes: []ProcessInfo{
		{PID: 9001, Name: "ssh-agent.exe", CreationUnixNano: 41},
	}}
	phase := NewBrokersPhase(controller, clock)
	engage := phase.Engage(context.Background())
	if engage.Status != PhaseApplied || engage.Targets != 1 {
		t.Fatalf("unexpected broker engage: %+v", engage)
	}
	if !strings.Contains(engage.Detail, BrokerStatusFrozenNotLocked) {
		t.Fatalf("the honest frozen-not-locked status is missing: %q", engage.Detail)
	}
	if err := phase.Verify(context.Background()); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("the missing process read-back was not reported: %v", err)
	}
	release := phase.Release(context.Background())
	if release.Status != PhaseApplied || release.Targets != 1 {
		t.Fatalf("unexpected broker release: %+v", release)
	}
}

func TestBrokersPhaseWithoutControllerIsNotImplemented(t *testing.T) {
	phase := NewBrokersPhase(nil, newFakeClock())
	engage := phase.Engage(context.Background())
	if engage.Status != PhaseUnavailable || !strings.Contains(engage.Detail, "NOT_IMPLEMENTED") {
		t.Fatalf("the missing controller was not reported honestly: %+v", engage)
	}
}

func TestBrokerFreezeScanFailureIsReported(t *testing.T) {
	controller := &fakeProcessController{listErr: errors.New("snapshot denied")}
	freezer := NewBrokerFreezer()
	report, err := freezer.Freeze(context.Background(), controller, newFakeClock().Now())
	if err == nil {
		t.Fatal("a failed process scan was not reported")
	}
	if report.Status != "scan-failed" {
		t.Fatalf("unexpected report: %+v", report)
	}
}
